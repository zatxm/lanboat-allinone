package nativecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zatxm/lanboat-allinone/native"
)

func executeSudokuForward(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("sudoku-forward", flag.ContinueOnError)
	f.SetOutput(out)
	listen := f.String("listen", "127.0.0.1:0", "local TCP listen address")
	endpoint := f.String("url", "", "public ws:// or wss:// Sudoku route")
	ca := f.String("ca", "", "trusted CA certificate file for wss")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" || f.NArg() != 0 {
		return errors.New("usage: sudoku-forward -url ws[s]://host/path [-listen 127.0.0.1:port] [-ca file]")
	}
	r, err := native.New(ctx, []byte(`{"log":{"disabled":true}}`), nil)
	if err != nil {
		return err
	}
	defer r.Close()
	if err = r.Start(); err != nil {
		return err
	}
	forward, err := r.ForwardSudokuWebSocket(ctx, *listen, *endpoint, native.TLSOptions{CertificatePath: *ca})
	if err != nil {
		return err
	}
	defer forward.Close()
	if _, err = fmt.Fprintln(out, forward.Addr()); err != nil {
		return err
	}
	return forward.Wait()
}

func generateSudoku(args []string, out io.Writer) error {
	if args[0] == "sudoku-keypair" {
		if len(args) != 1 {
			return errors.New("usage: generate sudoku-keypair")
		}
		pair, err := native.GenerateSudokuKeyPair()
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(pair)
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("key-file", "", "file containing the master or split private key")
	if err := f.Parse(args[1:]); err != nil || *path == "" || f.NArg() != 0 {
		return errors.New("usage: generate sudoku-<split|public> -key-file file")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil {
		return err
	}
	defer clear(b)
	if len(b) > 512 {
		return errors.New("oversized Sudoku private key file")
	}
	var key string
	if args[0] == "sudoku-split" {
		key, err = native.SplitSudokuPrivateKey(strings.TrimSpace(string(b)))
	} else {
		key, err = native.RecoverSudokuPublicKey(strings.TrimSpace(string(b)))
	}
	if err != nil {
		return err
	}
	field := "public_key"
	if args[0] == "sudoku-split" {
		field = "private_key"
	}
	return json.NewEncoder(out).Encode(map[string]string{field: key})
}
