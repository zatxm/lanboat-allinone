package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/hdevalence/ed25519consensus"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// Independent wire vectors are generated and checked by the official library
// in this separate process. This package is never part of the product graph.
func lockOracle() {
	var setup struct{ Wrapping []byte }
	must(json.NewDecoder(os.Stdin).Decode(&setup))
	a, b, c, rotation := key.NewNLPrivate(), key.NewNLPrivate(), key.NewNLPrivate(), key.NewNLPrivate()
	secret := []byte("test-only-disablement-secret-32byt")
	state := tka.State{Keys: []tka.Key{{Kind: tka.Key25519, Votes: 1, Public: a.KeyID()}, {Kind: tka.Key25519, Votes: 3, Public: b.KeyID()}}, DisablementValues: [][]byte{tka.DisablementKDF(secret)}, StateID1: 123, StateID2: 456}
	storage := tka.ChonkMem()
	authority, genesis, e := tka.Create(storage, state, a)
	must(e)
	fixture := map[string]any{"genesis": genesis.Serialize(), "secret": secret, "derived": state.DisablementValues[0]}
	node, rotated := key.NewNode().Public(), key.NewNode().Public()
	nodeBytes, _ := node.MarshalBinary()
	rotatedBytes, _ := rotated.MarshalBinary()
	sign := func(s tka.NodeKeySignature, k key.NLPrivate) tka.NodeKeySignature {
		s.Signature, e = k.SignNKS(s.SigHash())
		must(e)
		return s
	}
	direct := sign(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: nodeBytes, KeyID: a.KeyID(), WrappingPubkey: rotation.KeyID()}, a)
	rotatedSig, e := tka.ResignNKS(rotation, rotated, direct.Serialize())
	must(e)
	credential := sign(tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: a.KeyID(), WrappingPubkey: rotation.KeyID()}, a)
	delegated := sign(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: nodeBytes, Nested: &credential, WrappingPubkey: rotation.KeyID()}, rotation)
	for _, row := range []struct {
		k   key.NodePublic
		sig []byte
	}{{node, direct.Serialize()}, {rotated, rotatedSig}, {node, delegated.Serialize()}} {
		must(authority.NodeKeyAuthorized(row.k, row.sig))
	}
	local := direct
	local.WrappingPubkey = setup.Wrapping
	local = sign(local, a)
	fixture["local"] = local.Serialize()
	fixture["node"], fixture["rotated"], fixture["direct"], fixture["rotation"], fixture["credential"] = nodeBytes, rotatedBytes, direct.Serialize(), rotatedSig, delegated.Serialize()
	var chain [][]byte
	var heads []string
	appendAUM := func(update tka.AUM, signer key.NLPrivate) tka.AUM {
		h := authority.Head()
		update.PrevAUMHash = h[:]
		update.Signatures, e = signer.SignAUM(update.SigHash())
		must(e)
		must(authority.Inform(storage, []tka.AUM{update}))
		chain = append(chain, update.Serialize())
		heads = append(heads, authority.Head().String())
		return update
	}
	appendAUM(tka.AUM{MessageKind: tka.AUMAddKey, Key: &tka.Key{Kind: tka.Key25519, Votes: 1, Public: c.KeyID()}}, a)
	votes := uint(2)
	appendAUM(tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: c.KeyID(), Votes: &votes, Meta: map[string]string{"name": "第三签名者"}}, a)
	appendAUM(tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: a.KeyID()}, b)
	checkpoint := state
	checkpoint.Keys = []tka.Key{{Kind: tka.Key25519, Votes: 3, Public: b.KeyID()}, {Kind: tka.Key25519, Votes: 2, Public: c.KeyID(), Meta: map[string]string{"name": "第三签名者"}}}
	appendAUM(tka.AUM{MessageKind: tka.AUMCheckpoint, State: &checkpoint}, b)
	appendAUM(tka.AUM{MessageKind: tka.AUMNoOp}, c)
	fixture["updates"], fixture["heads"] = chain, heads
	// Equal-weight removal takes precedence, regardless of arrival order.
	forks := []tka.AUM{{MessageKind: tka.AUMAddKey, Key: &tka.Key{Kind: tka.Key25519, Votes: 1, Public: c.KeyID()}}, {MessageKind: tka.AUMNoOp}, {MessageKind: tka.AUMRemoveKey, KeyID: a.KeyID()}}
	var forkBytes [][]byte
	g := genesis.Hash()
	for i := range forks {
		forks[i].PrevAUMHash = g[:]
		k := b
		if i == 0 {
			k = a
		}
		forks[i].Signatures, e = k.SignAUM(forks[i].SigHash())
		must(e)
		forkBytes = append(forkBytes, forks[i].Serialize())
	}
	forkStore := tka.ChonkMem()
	forkAuth, e := tka.Bootstrap(forkStore, genesis)
	must(e)
	must(forkAuth.Inform(forkStore, forks))
	fixture["forks"], fixture["fork_head"] = forkBytes, forkAuth.Head().String()
	// ZIP215 torsion/noncanonical encodings generated without test-vector copies.
	var vectors []map[string]any
	for _, y := range []byte{0, 1, 0xec, 0xed, 0xee} {
		for _, signbit := range []byte{0, 128} {
			pub := make([]byte, 32)
			pub[0] = y
			if y >= 0xec {
				for i := 1; i < 32; i++ {
					pub[i] = 255
				}
				pub[31] = 127
			}
			pub[31] |= signbit
			for _, r0 := range []byte{0, 1, 0xec, 0xed, 0xee} {
				sig := make([]byte, 64)
				sig[0] = r0
				if r0 >= 0xec {
					for i := 1; i < 32; i++ {
						sig[i] = 255
					}
					sig[31] = 127
				}
				message := []byte("independent ZIP215 oracle")
				vectors = append(vectors, map[string]any{"key": pub, "message": message, "signature": sig, "valid": ed25519consensus.Verify(ed25519.PublicKey(pub), message, sig)})
			}
		}
	}
	fixture["zip215"] = vectors
	credPub, credPrivate, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	wrappedCredential := sign(tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: a.KeyID(), WrappingPubkey: credPub}, a)
	fixture["wrapped"] = "test-only-auth--TL" + base64.RawStdEncoding.EncodeToString(wrappedCredential.Serialize()) + "-" + base64.RawStdEncoding.EncodeToString(credPrivate)
	json.NewEncoder(os.Stdout).Encode(fixture)
	// Check a rotation produced by Lanboat using an official trust root.
	var request struct{ Node, Signature []byte }
	must(json.NewDecoder(os.Stdin).Decode(&request))
	var received key.NodePublic
	must(received.UnmarshalBinary(request.Node))
	original, e := tka.Bootstrap(tka.ChonkMem(), genesis)
	must(e)
	json.NewEncoder(os.Stdout).Encode(map[string]bool{"valid": original.NodeKeyAuthorized(received, request.Signature) == nil})
}
