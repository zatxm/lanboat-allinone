package nativecmd

import (
	"errors"
	"flag"
	"github.com/zatxm/lanboat-allinone/v26/native"
	"io"
	"os"
)

func executeRuleSet(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "compile" && args[0] != "convert" {
		return errors.New("rule-set <compile|convert> [-type adguard] -o output.srs input")
	}
	flags := flag.NewFlagSet("rule-set", flag.ContinueOnError)
	flags.SetOutput(out)
	output := flags.String("o", "", "output file")
	kind := flags.String("type", "adguard", "conversion format")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 1 || *output == "" {
		return errors.New("input and -o output are required")
	}
	format := "source"
	if args[0] == "convert" {
		if *kind != "adguard" {
			return errors.New("conversion type must be adguard")
		}
		format = "adguard"
	}
	file, e := os.Open(flags.Arg(0))
	if e != nil {
		return e
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if e != nil {
		return e
	}
	data, e = native.CompileRuleSet(data, format)
	if e != nil {
		return e
	}
	return os.WriteFile(*output, data, 0600)
}
