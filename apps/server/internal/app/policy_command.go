package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func policyCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, err := fmt.Fprintln(stdout, "usage: hasp policy (show|set|validate) [options]")
		return err
	}
	switch args[0] {
	case "show":
		return policyShowCommand(ctx, args[1:], stdout, s)
	case "set":
		return policySetCommand(ctx, args[1:], stdout, s)
	case "validate":
		return policyValidateCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

func policyShowCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp policy show [--json]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.Policy(ctx)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderPolicy(stdout, reply.PolicyDocument)
}

func policySetCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("policy set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("file", "", "")
	force := fs.Bool("force", false, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*filePath) == "" {
		return errors.New("usage: hasp policy set --file=<path> [--force] [--json]")
	}
	doc, err := readPolicyFile(*filePath)
	if err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.SetPolicy(ctx, runtime.PolicySetRequest{
		Policy:    doc,
		IfMatch:   doc.Version,
		Force:     *force,
		UpdatedBy: "cli",
	})
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	_, err = fmt.Fprintf(stdout, "Policy updated to version %s (%d rules).\n", reply.Version, len(reply.Rules))
	return err
}

func policyValidateCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("file", "", "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*filePath) == "" {
		return errors.New("usage: hasp policy validate --file=<path> [--json]")
	}
	doc, err := readPolicyFile(*filePath)
	if err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err := client.SetPolicy(ctx, runtime.PolicySetRequest{Policy: doc, ValidateOnly: true}); err != nil {
		return err
	}
	payload := map[string]any{"valid": true, "rule_count": len(doc.Rules)}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, payload)
	}
	_, err = fmt.Fprintf(stdout, "Policy valid (%d rules).\n", len(doc.Rules))
	return err
}

func readPolicyFile(path string) (runtime.PolicyDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtime.PolicyDocument{}, fmt.Errorf("read policy file: %w", err)
	}
	var doc runtime.PolicyDocument
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return runtime.PolicyDocument{}, fmt.Errorf("decode policy file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return runtime.PolicyDocument{}, errors.New("decode policy file: policy file must contain exactly one JSON object")
	}
	return doc, nil
}

func renderPolicy(w io.Writer, policy runtime.PolicyDocument) error {
	if len(policy.Rules) == 0 {
		_, err := fmt.Fprintf(w, "Policy version %s has no rules.\n", policy.Version)
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCONSUMER\tSECRET\tSCOPE\tDECISION\tTTL\tMAX")
	for _, rule := range policy.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			rule.ID,
			rule.Match.Consumer,
			rule.Match.Secret,
			rule.Match.Scope,
			rule.Decision,
			rule.TTLS,
			rule.MaxConcurrent,
		)
	}
	return tw.Flush()
}
