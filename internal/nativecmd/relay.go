package nativecmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zatxm/lanboat-allinone/native"
)

func executeRelayBind(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("relay-bind", flag.ContinueOnError)
	flags.SetOutput(out)
	file := flags.String("c", "config.json", "configuration file")
	tag := flags.String("outbound", "proxy", "Relay outbound tag")
	listen := flags.String("listen", "127.0.0.1:0", "remote IP and port")
	target := flags.String("target", "", "client-side target host:port")
	network := flags.String("network", "tcp", "tcp or udp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *target == "" {
		return errors.New("relay-bind requires -target host:port and no positional arguments")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	r, err := native.New(ctx, raw, nil)
	if err != nil {
		return err
	}
	defer r.Close()
	if err = r.Start(); err != nil {
		return err
	}
	forward, err := r.ForwardRelay(ctx, *tag, *network, *listen, *target)
	if err != nil {
		return err
	}
	defer forward.Close()
	if _, err = fmt.Fprintln(out, forward.Addr()); err != nil {
		return err
	}
	return forward.Wait()
}
