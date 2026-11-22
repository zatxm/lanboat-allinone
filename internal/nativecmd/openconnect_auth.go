package nativecmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"

	"github.com/zatxm/lanboat-allinone/v26/native"
)

func openConnectBrowser(executable string) native.OpenConnectAuthHandler {
	return func(ctx context.Context, form native.OpenConnectAuthForm) (map[string]string, error) {
		if form.SSO == nil || form.SSO.Mode != "external" {
			return nil, &native.OpenConnectAuthRequiredError{Form: form}
		}
		for _, f := range form.Fields {
			if f.Type != "sso" && (f.Type != "select" || f.Value == "") {
				return nil, &native.OpenConnectAuthRequiredError{Form: form}
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// No shell, credentials, or server-supplied arguments; browser lifetime is independent of the VPN.
		cmd := exec.Command(executable, form.SSO.LoginURL)
		if err := cmd.Start(); err != nil {
			return nil, errors.New("cannot start OpenConnect authentication browser")
		}
		go func() { _ = cmd.Wait() }()
		return nil, nil
	}
}

// A single bounded reader and serialized prompts keep concurrent endpoints isolated.
func openConnectStdio(ctx context.Context, input io.Reader, out io.Writer) native.OpenConnectAuthHandler {
	type response struct {
		RequestID uint64            `json:"request_id"`
		Values    map[string]string `json:"values"`
		Cancel    bool              `json:"cancel"`
		err       error
	}
	answers := make(chan response, 1)
	gate := make(chan struct{}, 1)
	var sequence uint64
	go func() {
		defer close(answers)
		scan := bufio.NewScanner(input)
		scan.Buffer(make([]byte, 4096), 65536)
		for scan.Scan() {
			var v response
			if json.Unmarshal(scan.Bytes(), &v) != nil {
				v.err = errors.New("invalid OpenConnect authentication reply")
			}
			select {
			case answers <- v:
			case <-ctx.Done():
				return
			}
		}
		if err := scan.Err(); err != nil {
			select {
			case answers <- response{err: errors.New("OpenConnect authentication input exceeds limits or cannot be read")}:
			case <-ctx.Done():
			}
		}
	}()
	return func(call context.Context, form native.OpenConnectAuthForm) (map[string]string, error) {
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		case <-call.Done():
			return nil, call.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		sequence++
		if err := json.NewEncoder(out).Encode(struct {
			Type      string                     `json:"type"`
			RequestID uint64                     `json:"request_id"`
			Form      native.OpenConnectAuthForm `json:"form"`
		}{"openconnect-auth", sequence, form}); err != nil {
			return nil, err
		}
		for {
			select {
			case v, ok := <-answers:
				if !ok {
					return nil, io.EOF
				}
				if v.err != nil {
					return nil, v.err
				}
				if v.RequestID != sequence {
					continue
				}
				if v.Cancel {
					return nil, context.Canceled
				}
				return v.Values, nil
			case <-call.Done():
				return nil, call.Err()
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
}
