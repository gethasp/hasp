package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

type telemetryStatusPayload struct {
	Enabled             bool               `json:"enabled"`
	BlockedByEnv        bool               `json:"blocked_by_env"`
	LastPingAt          string             `json:"last_ping_at,omitempty"`
	InstallIDHashPrefix string             `json:"install_id_hash_prefix,omitempty"`
	Endpoint            string             `json:"endpoint,omitempty"`
	SchemaVersion       int                `json:"schema_version"`
	Commands24h         int                `json:"commands_24h"`
	CommandsTotal       int                `json:"commands_total"`
	WouldSend           bool               `json:"would_send"`
	Reason              string             `json:"reason,omitempty"`
	Payload             *telemetry.Payload `json:"payload,omitempty"`
}

func telemetryCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"telemetry"})
	}
	switch args[0] {
	case "status":
		return telemetryStatusCommand(ctx, args[1:], stdout, false)
	case "preview":
		return telemetryStatusCommand(ctx, args[1:], stdout, true)
	case "enable":
		return telemetryEnableCommand(ctx, args[1:], stdin, stdout)
	case "disable":
		return telemetryDisableCommand(ctx, args[1:], stdout)
	case "forget":
		return telemetryForgetCommand(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown telemetry subcommand %q", args[0])
	}
}

func telemetryStatusCommand(ctx context.Context, args []string, stdout io.Writer, includePayload bool) error {
	commandName := "telemetry status"
	usage := "usage: hasp telemetry status [--json]"
	if includePayload {
		commandName = "telemetry preview"
		usage = "usage: hasp telemetry preview [--json]"
	}
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(usage)
	}
	status, err := telemetryStatus(includePayload)
	if err != nil {
		return err
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, status, func(w io.Writer) error {
		if includePayload {
			if !status.WouldSend {
				_, err := fmt.Fprintf(w, "telemetry preview unavailable: %s\n", status.Reason)
				return err
			}
			data, err := telemetry.EncodePayload(*status.Payload)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(w, "%s\n", data)
			return err
		}
		state := "disabled"
		if status.Enabled {
			state = "enabled"
		}
		if status.BlockedByEnv {
			state = "blocked by " + telemetry.EnvDisabled
		}
		if _, err := fmt.Fprintf(w, "telemetry: %s\n", state); err != nil {
			return err
		}
		if status.Endpoint != "" {
			if _, err := fmt.Fprintf(w, "endpoint: %s\n", status.Endpoint); err != nil {
				return err
			}
		}
		if status.InstallIDHashPrefix != "" {
			if _, err := fmt.Fprintf(w, "install hash prefix: %s\n", status.InstallIDHashPrefix); err != nil {
				return err
			}
		}
		if status.LastPingAt != "" {
			if _, err := fmt.Fprintf(w, "last ping: %s\n", status.LastPingAt); err != nil {
				return err
			}
		}
		return nil
	})
}

func telemetryEnableCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("telemetry enable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp telemetry enable [--yes] [--json]")
	}
	if telemetry.DisabledByEnv() {
		return fmt.Errorf("%s is set; remove it before enabling telemetry", telemetry.EnvDisabled)
	}
	if !*yes && !globalFlagsFromContext(ctx).yes {
		if _, err := fmt.Fprintln(stdout, telemetryConsentSummary()); err != nil {
			return err
		}
		if !confirmTelemetry(stdin, stdout) {
			return errors.New("telemetry enable cancelled")
		}
	}
	state, err := telemetry.DefaultStore().Enable(time.Now().UTC())
	if err != nil {
		return err
	}
	status := telemetryStatusPayload{
		Enabled:       state.Enabled,
		SchemaVersion: telemetry.SchemaVersion,
		Endpoint:      strings.TrimSpace(telemetry.Endpoint),
		WouldSend:     telemetryEndpointTrusted(),
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, status, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, "telemetry enabled")
		return err
	})
}

func telemetryDisableCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("telemetry disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp telemetry disable [--json]")
	}
	state, err := telemetry.DefaultStore().Disable()
	if err != nil {
		return err
	}
	status := telemetryStatusPayload{
		Enabled:       state.Enabled,
		BlockedByEnv:  telemetry.DisabledByEnv(),
		SchemaVersion: telemetry.SchemaVersion,
		Endpoint:      strings.TrimSpace(telemetry.Endpoint),
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, status, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, "telemetry disabled")
		return err
	})
}

func telemetryForgetCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("telemetry forget", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp telemetry forget [--json]")
	}
	hashes, err := telemetry.DefaultStore().Forget()
	if err != nil {
		return err
	}
	erasure := "not_requested"
	if len(hashes) > 0 && telemetryEndpointTrusted() && !telemetry.DisabledByEnv() {
		erasure = "requested"
		if err := (telemetry.Client{}).SendErasures(ctx, hashes); err != nil {
			erasure = "failed"
			if stderr != nil {
				fmt.Fprintf(stderr, "telemetry erasure request failed; contact privacy@gethasp.com with install hash prefix %s\n", hashPrefix(hashes[0]))
			}
		}
	}
	payload := map[string]any{
		"enabled":        false,
		"blocked_by_env": telemetry.DisabledByEnv(),
		"erasure":        erasure,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, "telemetry forgotten")
		return err
	})
}

func telemetryStatus(includePayload bool) (telemetryStatusPayload, error) {
	state, err := telemetry.DefaultStore().Load()
	if err != nil {
		return telemetryStatusPayload{}, err
	}
	status := telemetryStatusPayload{
		Enabled:       state.Enabled,
		BlockedByEnv:  telemetry.DisabledByEnv(),
		Endpoint:      strings.TrimSpace(telemetry.Endpoint),
		SchemaVersion: telemetry.SchemaVersion,
		Commands24h:   state.Commands24h,
		CommandsTotal: state.CommandsTotal,
	}
	if !state.LastPingAt.IsZero() {
		status.LastPingAt = state.LastPingAt.UTC().Format(time.RFC3339)
	}
	if state.InstallID != "" && state.InstallYear > 0 {
		status.InstallIDHashPrefix = hashPrefix(telemetry.InstallHash(state.InstallID, state.InstallYear))
	}
	status.WouldSend = state.Enabled && !status.BlockedByEnv && telemetryEndpointTrusted()
	switch {
	case !state.Enabled:
		status.Reason = "telemetry is disabled"
	case status.BlockedByEnv:
		status.Reason = telemetry.EnvDisabled + " is set"
	case !telemetryEndpointTrusted():
		status.Reason = "telemetry endpoint is not configured"
	}
	if includePayload && status.WouldSend {
		payload, updated, err := telemetry.BuildPayload(state, telemetry.BuildOptions{
			HaspVersion:   runtime.VersionString(),
			InstallMethod: "unknown",
			Now:           time.Now().UTC(),
		})
		if err != nil {
			return telemetryStatusPayload{}, err
		}
		if updated.InstallID != state.InstallID || updated.InstallYear != state.InstallYear {
			_ = telemetry.DefaultStore().Save(updated)
		}
		status.Payload = &payload
	}
	return status, nil
}

func telemetryEndpointTrusted() bool {
	_, err := telemetry.ValidateEndpoint(telemetry.Endpoint)
	return err == nil && strings.TrimSpace(telemetry.Endpoint) != ""
}

func telemetryConsentSummary() string {
	return strings.Join([]string{
		"HASP telemetry is optional and disabled by default.",
		"It sends daily aggregate command and reliability counters to telemetry.gethasp.com.",
		"It never sends secrets, secret names, aliases, refs, paths, repo names, args, stdout/stderr, raw errors, or audit logs.",
		"Use HASP_TELEMETRY_DISABLED=1 to block it at runtime, or `hasp telemetry forget` to delete local telemetry state.",
	}, "\n")
}

func confirmTelemetry(stdin io.Reader, stdout io.Writer) bool {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if stdout != nil {
		fmt.Fprint(stdout, "Enable telemetry? [y/N]: ")
	}
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if stdout != nil {
		fmt.Fprintln(stdout)
	}
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func hashPrefix(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
