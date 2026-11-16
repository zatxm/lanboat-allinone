package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// The official testcontrol TKA helper insists on its *current* capability
// number, even for unchanged schemas. This small control fixture instead uses
// official Noise, wire types and signatures while accepting the real client
// capability number. It does not advertise unimplemented newer capabilities.
func lockNoiseOracle() {
	machine, signer, peer, disco := key.NewMachine(), key.NewNLPrivate(), key.NewNode(), key.NewDisco()
	state := tka.State{Keys: []tka.Key{{Kind: tka.Key25519, Votes: 1, Public: signer.KeyID()}}, DisablementValues: [][]byte{tka.DisablementKDF([]byte("test-only-disablement-secret-32byt"))}}
	authority, genesis, e := tka.Create(tka.ChonkMem(), state, signer)
	must(e)
	sign := func(node key.NodePublic) []byte {
		b, _ := node.MarshalBinary()
		s := tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: b, KeyID: signer.KeyID()}
		s.Signature, e = signer.SignNKS(s.SigHash())
		must(e)
		must(authority.NodeKeyAuthorized(node, s.Serialize()))
		return s.Serialize()
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/register":
			var req tailcfg.RegisterRequest
			must(json.NewDecoder(r.Body).Decode(&req))
			if req.Auth == nil || req.Auth.AuthKey != "test-only-auth" {
				http.Error(w, "auth", 403)
				return
			}
			json.NewEncoder(w).Encode(tailcfg.RegisterResponse{MachineAuthorized: true})
		case "/machine/map":
			var req tailcfg.MapRequest
			must(json.NewDecoder(r.Body).Decode(&req))
			if !req.Stream {
				w.Write([]byte("{}"))
				return
			}
			self := &tailcfg.Node{ID: 1, StableID: "n1", Name: "native.test.ts.net.", User: 1, Key: req.NodeKey, KeySignature: sign(req.NodeKey), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}
			other := &tailcfg.Node{ID: 2, StableID: "n2", Name: "reference.test.ts.net.", User: 1, Key: peer.Public(), DiscoKey: disco.Public(), KeySignature: sign(peer.Public()), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
			response := tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{other}, TKAInfo: &tailcfg.TKAInfo{Head: authority.Head().String()}, PacketFilter: []tailcfg.FilterRule{{SrcIPs: []string{"*"}, DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRange{First: 0, Last: 65535}}}}}}
			b, e := json.Marshal(response)
			must(e)
			w.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(b))))
			w.Write(b)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/machine/tka/bootstrap":
			var req tailcfg.TKABootstrapRequest
			must(json.NewDecoder(r.Body).Decode(&req))
			if req.Version < 43 || req.NodeKey.IsZero() {
				http.Error(w, "invalid bootstrap", 400)
				return
			}
			json.NewEncoder(w).Encode(tailcfg.TKABootstrapResponse{GenesisAUM: genesis.Serialize()})
		default:
			http.NotFound(w, r)
		}
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tailcfg.OverTLSPublicKeyResponse{PublicKey: machine.Public()})
	})
	mux.HandleFunc("/ts2021", func(w http.ResponseWriter, r *http.Request) {
		conn, e := controlhttpserver.AcceptHTTP(r.Context(), w, r, machine, nil)
		if e != nil {
			return
		}
		defer conn.Close()
		var server http2.Server
		server.ServeConn(conn, &http2.ServeConnOpts{Context: context.Background(), Handler: handler})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]string{"control_url": server.URL})
	bufio.NewScanner(os.Stdin).Scan()
}
