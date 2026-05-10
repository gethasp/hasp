package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func accessCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, err := fmt.Fprintln(stdout, "usage: hasp access matrix [options]")
		return err
	}
	switch args[0] {
	case "matrix":
		return accessMatrixCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown access subcommand %q", args[0])
	}
}

func accessMatrixCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("access matrix", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	consumer := fs.String("consumer", "", "")
	secret := fs.String("secret", "", "")
	scope := fs.String("scope", "", "")
	source := fs.String("source", "", "")
	hasActiveLease := fs.String("has-active-lease", "", "")
	cursor := fs.String("cursor", "", "")
	limit := fs.Int("limit", 100, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp access matrix [--json] [--consumer=<id>] [--secret=<id>] [--scope=<scope>] [--source=policy|manual] [--has-active-lease=true|false] [--cursor=<cursor>] [--limit=<n>]")
	}
	req := runtime.AccessMatrixRequest{
		Consumer: strings.TrimSpace(*consumer),
		Secret:   strings.TrimSpace(*secret),
		Scope:    strings.TrimSpace(*scope),
		Source:   strings.TrimSpace(*source),
		Cursor:   strings.TrimSpace(*cursor),
		Limit:    *limit,
	}
	if raw := strings.TrimSpace(*hasActiveLease); raw != "" {
		switch raw {
		case "true", "1", "t", "TRUE", "True":
			value := true
			req.HasActiveLease = &value
		case "false", "0", "f", "FALSE", "False":
			value := false
			req.HasActiveLease = &value
		default:
			return fmt.Errorf("invalid has-active-lease %q", raw)
		}
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.AccessMatrix(ctx, req)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderAccessMatrix(stdout, reply.Grants)
}

func renderAccessMatrix(w io.Writer, grants []runtime.AccessMatrixGrant) error {
	if len(grants) == 0 {
		_, err := fmt.Fprintln(w, "No access grants.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONSUMER\tSECRET\tSCOPE\tSOURCE\tLEASES\tLAST_USED")
	for _, grant := range grants {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
			grant.ConsumerID,
			grant.SecretID,
			grant.Scope,
			grant.Source,
			grant.LeaseCount,
			grant.LastUsedAt,
		)
	}
	return tw.Flush()
}
