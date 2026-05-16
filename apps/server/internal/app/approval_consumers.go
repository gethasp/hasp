package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func approvalCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, err := fmt.Fprintln(stdout, "usage: hasp approval list [options]")
		return err
	}
	switch args[0] {
	case "list":
		return approvalListCommand(ctx, args[1:], stdout, s)
	case "decide":
		return errors.New("approval decisions require the trusted local app approval path")
	default:
		return fmt.Errorf("unknown approval subcommand %q", args[0])
	}
}

func approvalListCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("approval list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	status := fs.String("status", "", "")
	consumer := fs.String("consumer", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp approval list [--json] [--status=pending|granted|denied|expired] [--consumer=<id>]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.ListApprovals(ctx, runtime.ListApprovalsRequest{
		Status:     strings.TrimSpace(*status),
		ConsumerID: strings.TrimSpace(*consumer),
	})
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderApprovalList(stdout, reply.Approvals)
}

func approvalDecideCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("approval decide", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	grant := fs.Bool("grant", false, "")
	deny := fs.Bool("deny", false, "")
	ttl := fs.Duration("ttl", 0, "")
	scope := fs.String("scope", "", "")
	reason := fs.String("reason", "", "")
	authMethod := fs.String("auth-method", "", "")
	holdProof := fs.Duration("hold-proof", 0, "")
	if err := fs.Parse(normalizeApprovalDecideArgs(args)); err != nil {
		return err
	}
	if *grant == *deny {
		return errors.New("choose exactly one of --grant or --deny")
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp approval decide <approval-id> (--grant [--ttl=<duration>] [--scope=<scope>] | --deny [--reason=<text>]) [--json]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	req := runtime.DecideApprovalRequest{
		ApprovalID: strings.TrimSpace(fs.Arg(0)),
		Scope:      strings.TrimSpace(*scope),
		Reason:     strings.TrimSpace(*reason),
	}
	if *grant {
		req.Decision = "grant"
		req.AuthMethod = strings.TrimSpace(*authMethod)
		req.HoldDurationMS = int(holdProof.Milliseconds())
		if req.AuthMethod != "touch-id" && req.AuthMethod != "device-owner" {
			return errors.New("approval grant requires --auth-method touch-id|device-owner")
		}
		if *holdProof < 1500*time.Millisecond {
			return errors.New("approval grant requires --hold-proof >= 1500ms")
		}
		if *ttl > 0 {
			req.GrantedTTLS = int(ttl.Seconds())
		}
	} else {
		req.Decision = "deny"
		if strings.TrimSpace(*authMethod) != "" || *holdProof != 0 {
			return errors.New("--auth-method and --hold-proof are only valid for --grant")
		}
	}
	reply, err := client.DecideApproval(ctx, req)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	if req.Decision == "grant" {
		_, err = fmt.Fprintf(stdout, "Granted approval %s\n", req.ApprovalID)
		return err
	}
	_, err = fmt.Fprintf(stdout, "Denied approval %s\n", req.ApprovalID)
	return err
}

func normalizeApprovalDecideArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			flags = append(flags, arg)
			if (arg == "--ttl" || arg == "--scope" || arg == "--reason" || arg == "--auth-method" || arg == "--hold-proof") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
}

func renderApprovalList(w io.Writer, approvals []runtime.Approval) error {
	if len(approvals) == 0 {
		_, err := fmt.Fprintln(w, "No approvals.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tID\tCONSUMER\tSECRET\tSCOPE\tREQUESTED\tEXPIRES")
	for _, approval := range approvals {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			approval.Status,
			approval.ID,
			approval.RequesterConsumerID,
			approval.SecretID,
			approval.RequestedScope,
			approval.RequestedAt.Format(secrettypes.TimeRFC3339),
			approval.ExpiresAt.Format(secrettypes.TimeRFC3339),
		)
	}
	return tw.Flush()
}
