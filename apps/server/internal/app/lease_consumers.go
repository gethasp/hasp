package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func leaseCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, err := fmt.Fprintln(stdout, "usage: hasp lease (list|revoke) [options]")
		return err
	}
	switch args[0] {
	case "list":
		return leaseListCommand(ctx, args[1:], stdout, s)
	case "revoke":
		return leaseRevokeCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown lease subcommand %q", args[0])
	}
}

func leaseListCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("lease list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	consumer := fs.String("consumer", "", "")
	status := fs.String("status", "", "")
	expiringIn := fs.Duration("expiring-in", 0, "")
	cursor := fs.String("cursor", "", "")
	limit := fs.Int("limit", 100, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp lease list [--json] [--consumer=<id>] [--status=active|revoked|expired] [--expiring-in=<duration>] [--cursor=<cursor>] [--limit=<n>]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	req := runtime.ListLeasesRequest{
		ConsumerID: strings.TrimSpace(*consumer),
		Status:     strings.TrimSpace(*status),
		Cursor:     strings.TrimSpace(*cursor),
		Limit:      *limit,
	}
	if *expiringIn > 0 {
		req.ExpiringInSeconds = int(expiringIn.Seconds())
	}
	reply, err := client.ListLeases(ctx, req)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderLeaseList(stdout, reply.Leases)
}

func leaseRevokeCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("lease revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	reason := fs.String("reason", "", "")
	allForConsumer := fs.String("all-for-consumer", "", "")
	if err := fs.Parse(normalizeLeaseRevokeArgs(args)); err != nil {
		return err
	}
	if strings.TrimSpace(*allForConsumer) != "" && fs.NArg() != 0 {
		return errors.New("choose either <lease-id> or --all-for-consumer")
	}
	if strings.TrimSpace(*allForConsumer) == "" && fs.NArg() != 1 {
		return errors.New("usage: hasp lease revoke <lease-id> [--reason=<text>] [--json] OR hasp lease revoke --all-for-consumer=<id> [--reason=<text>] [--json]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	req := runtime.RevokeLeaseRequest{
		Reason:         strings.TrimSpace(*reason),
		AllForConsumer: strings.TrimSpace(*allForConsumer),
	}
	if req.AllForConsumer == "" {
		req.LeaseID = strings.TrimSpace(fs.Arg(0))
	}
	reply, err := client.RevokeLease(ctx, req)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	if req.AllForConsumer != "" {
		_, err = fmt.Fprintf(stdout, "Revoked %d leases for %s\n", reply.RevokedCount, req.AllForConsumer)
		return err
	}
	if reply.Revoked {
		if reply.RevokedCount == 0 {
			_, err = fmt.Fprintf(stdout, "Lease %s was already revoked\n", req.LeaseID)
			return err
		}
		_, err = fmt.Fprintf(stdout, "Revoked lease %s\n", req.LeaseID)
		return err
	}
	return fmt.Errorf("lease %s not found or already revoked", req.LeaseID)
}

func normalizeLeaseRevokeArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			flags = append(flags, arg)
			if (arg == "--reason" || arg == "--all-for-consumer") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func renderLeaseList(w io.Writer, leases []runtime.Lease) error {
	if len(leases) == 0 {
		_, err := fmt.Fprintln(w, "No leases.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tID\tSECRET\tCONSUMER\tSCOPE\tLAST_USED\tEXPIRES")
	for _, lease := range leases {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			lease.Status,
			lease.ID,
			lease.SecretID,
			lease.ConsumerID,
			lease.Scope,
			lease.LastUsedAt.Format(secrettypes.TimeRFC3339),
			lease.ExpiresAt.Format(secrettypes.TimeRFC3339),
		)
	}
	return tw.Flush()
}
