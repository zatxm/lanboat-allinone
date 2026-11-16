package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTailscaleSSHRecordingReference(t *testing.T) {
	if !tsSSHPlatform() {
		return
	}
	t.Setenv("LANBOAT_TS_SSH", "1")
	t.Setenv("LANBOAT_TS_RECORDING", "1")
	control, decoder, input := startTSReference(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := func(value any, out any) {
		t.Helper()
		if e := json.NewEncoder(input).Encode(value); e != nil {
			t.Fatal(e)
		}
		if e := decoder.Decode(out); e != nil {
			t.Fatal(e)
		}
	}
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: control, StateDirectory: t.TempDir(), ForceDERP: true, Hostname: "record-native", SSHServer: TailscaleSSHOptions{Enabled: true}}}}, Route: Route{Final: "ts"}})
	status, e := r.TailscaleStatus(ctx, "ts")
	if e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	c.mu.Lock()
	var peer tsNode
	for _, n := range c.nodes {
		if n.Name == "reference.test.ts.net." {
			peer = n
		}
	}
	c.mu.Unlock()
	if len(peer.Addresses) == 0 {
		t.Fatal("recording peer absent")
	}
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(t.TempDir(), "lanboat-allinone")
	if b, e := exec.CommandContext(ctx, "go", "build", "-o", exe, "../cmd/lanboat-allinone").CombinedOutput(); e != nil {
		t.Fatal(e, string(b))
	}
	c.ssh.worker = exe
	var ok map[string]any
	policy := func(require bool) {
		t.Helper()
		action := map[string]any{"accept": true, "recorders": []string{netip.AddrPortFrom(peer.Addresses[0].Addr(), 8188).String()}}
		if require {
			action["onRecordingFailure"] = map[string]any{"RejectSessionWithMessage": "recording required", "TerminateSessionWithMessage": "recording stopped"}
		}
		value := map[string]any{"rules": []any{map[string]any{"principals": []any{map[string]bool{"any": true}}, "sshUsers": map[string]string{u.Username: u.Username}, "action": action}}}
		command(map[string]any{"Op": "ssh-policy", "Policy": value}, &ok)
		want, _ := json.Marshal(value)
		var parsed tsSSHPolicy
		json.Unmarshal(want, &parsed)
		for deadline := time.Now().Add(2 * time.Second); ; {
			c.mu.Lock()
			match := c.sshPolicy != nil && len(c.sshPolicy.Rules) == 1 && len(c.sshPolicy.Rules[0].Action.Recorders) == 1 && (c.sshPolicy.Rules[0].Action.OnRecordingFailure != nil) == require
			c.mu.Unlock()
			if match {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("recording policy not applied")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	policy(true)
	var bridge struct{ Address string }
	command(map[string]string{"Op": "ssh-bridge", "Address": net.JoinHostPort(status.Addresses[0].Addr().String(), "22")}, &bridge)
	_, port, e := net.SplitHostPort(bridge.Address)
	if e != nil {
		t.Fatal(e)
	}
	options := []string{"-F", "/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"}
	run := func(script string) (string, string, error) {
		t.Helper()
		args := append(append([]string{}, options...), "-p", port, "-l", u.Username, "127.0.0.1", script)
		cmd := exec.CommandContext(ctx, "ssh", args...)
		cmd.Stdin = strings.NewReader("")
		var output, stderr bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &stderr
		e := cmd.Run()
		return output.String(), stderr.String(), e
	}
	output, stderr, e := run("printf 'record-output-中文'; printf 'record-error' >&2")
	if e != nil || output != "record-output-中文" || stderr != "record-error" {
		t.Fatal("recorded command", e, output, stderr)
	}
	type session struct {
		Header map[string]any
		Events []json.RawMessage
	}
	var sessions []session
	command(map[string]string{"Op": "recording-status"}, &sessions)
	if len(sessions) != 1 || sessions[0].Header["version"] != float64(2) || sessions[0].Header["sshUser"] != u.Username {
		t.Fatal("cast header", sessions)
	}
	eventText := func(events []json.RawMessage) string {
		t.Helper()
		var out strings.Builder
		for _, b := range events {
			var event []any
			if e := json.Unmarshal(b, &event); e != nil {
				t.Fatal(e)
			}
			if len(event) != 3 {
				t.Fatal("invalid cast event", event)
			}
			if event[1] == "o" {
				out.WriteString(event[2].(string))
			}
		}
		return out.String()
	}
	text := eventText(sessions[0].Events)
	if !strings.Contains(text, "record-output-中文") || !strings.Contains(text, "record-error") {
		t.Fatal("missing output events", text)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	remote := filepath.Join(dir, "upload")
	secret := bytes.Repeat([]byte("unrecorded-file-payload"), 3000)
	os.WriteFile(source, secret, 0600)
	cmd := exec.CommandContext(ctx, "sftp", append(append([]string{}, options...), "-P", port, "-b", "-", u.Username+"@127.0.0.1")...)
	cmd.Stdin = strings.NewReader("put " + source + " " + remote + "\nrm " + remote + "\n")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatal("recorded SFTP", e, string(b))
	}
	command(map[string]string{"Op": "recording-status"}, &sessions)
	if len(sessions) != 2 {
		t.Fatal("SFTP recording missing", len(sessions))
	}
	audit := eventText(sessions[1].Events)
	if !strings.Contains(audit, remote) || !strings.Contains(audit, "operation") || strings.Contains(audit, "unrecorded-file-payload") {
		t.Fatal("SFTP audit leaked data or lost operations", audit)
	}
	command(map[string]string{"Op": "recording-mode", "Data": "reject"}, &ok)
	marker := filepath.Join(dir, "must-not-run")
	if out, errout, e := run("printf bad > " + marker); e == nil {
		t.Fatal("mandatory recording allowed unavailable recorder", out, errout)
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("unrecorded command executed")
	}
	policy(false)
	if out, errout, e := run("printf fail-open"); e != nil || out != "fail-open" {
		t.Fatal("recording fail-open policy", e, out, errout)
	}
	policy(true)
	command(map[string]string{"Op": "recording-mode", "Data": "drop"}, &ok)
	start := time.Now()
	output, stderr, e = run("printf running; sleep 30; printf should-not-run")
	if e == nil || time.Since(start) > 4*time.Second || strings.Contains(output, "should-not-run") {
		t.Fatal("recording failure did not terminate session", e, time.Since(start), output, stderr)
	}
}

func TestTailscaleSSHRecordedUTF8(t *testing.T) {
	reader, writer := io.Pipe()
	rec := &tsSSHRecording{pipe: writer, at: time.Now(), done: make(chan struct{}), cancel: func() {}, transport: &http.Transport{}}
	var output strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(rec.done)
		d := json.NewDecoder(reader)
		for {
			var e []any
			if err := d.Decode(&e); err != nil {
				return
			}
			output.WriteString(e[2].(string))
		}
	}()
	b := []byte("汉字😀")
	for _, part := range [][]byte{b[:1], b[1:5], b[5:8], b[8:]} {
		if e := rec.event(part); e != nil {
			t.Fatal(e)
		}
	}
	rec.close()
	<-done
	if output.String() != string(b) {
		t.Fatal("split UTF8 output corrupted", strconv.Quote(output.String()))
	}
}
