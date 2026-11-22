package nativecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/zatxm/lanboat-allinone/v26/native"
)

func executeMasqueProbe(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("masque-probe", flag.ContinueOnError)
	flags.SetOutput(out)
	file := flags.String("c", "config.json", "configuration file")
	tag := flags.String("outbound", "proxy", "CONNECT-IP client tag")
	timeout := flags.Duration("timeout", 15*time.Second, "probe time budget")
	peer := flags.String("peer", "", "known IPv6 peer;default ff02::1")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *tag == "" || *timeout <= 0 || *timeout > time.Minute {
		return errors.New("masque-probe requires a client tag,a timeout in (0,1m],and no positional arguments")
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
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var targets []netip.Addr
	if *peer != "" {
		address, err := netip.ParseAddr(*peer)
		if err != nil {
			return err
		}
		targets = append(targets, address)
	}
	status, err := r.ProbeMasquePath(ctx, *tag, targets...)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(status)
}
