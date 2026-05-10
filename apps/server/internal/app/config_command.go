package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func configCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		_, err := fmt.Fprintln(stdout, "usage: hasp config (show|get|set) [options]")
		return err
	}
	switch args[0] {
	case "show":
		return configShowCommand(ctx, args[1:], stdout, s)
	case "get":
		return configGetCommand(ctx, args[1:], stdout, s)
	case "set":
		return configSetCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown config subcommand %q", args[0])
	}
}

func configShowCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("config show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp config show [--json]")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.Config(ctx)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderConfig(stdout, reply.Config)
}

func configGetCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("config get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp config get <key> [--json]")
	}
	key := strings.TrimSpace(fs.Arg(0))
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.Config(ctx)
	if err != nil {
		return err
	}
	value, ok := reply.Config[key]
	if !ok {
		return fmt.Errorf("config key not found: %s", key)
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, runtime.ConfigValueResponse{Key: key, Value: value})
	}
	_, err = fmt.Fprintln(stdout, formatConfigValue(value))
	return err
}

func configSetCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("config set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: hasp config set <key> <value> [--json]")
	}
	key := strings.TrimSpace(fs.Arg(0))
	value, err := parseConfigCLIValue(fs.Arg(1))
	if err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.SetConfig(ctx, runtime.ConfigSetRequest{Key: key, Value: value, Actor: "cli"})
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	_, err = fmt.Fprintf(stdout, "%s = %s\n", reply.Key, formatConfigValue(reply.Value))
	return err
}

func parseConfigCLIValue(raw string) (any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if raw == "true" || raw == "false" {
		return raw == "true", nil
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return nil, fmt.Errorf("decode config array: %w", err)
		}
		return values, nil
	}
	if i, err := strconv.Atoi(raw); err == nil {
		return i, nil
	}
	return raw, nil
}

func renderConfig(w io.Writer, config runtime.ConfigDocument) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tVALUE")
	for _, key := range sortedConfigKeys(config) {
		fmt.Fprintf(tw, "%s\t%s\n", key, formatConfigValue(config[key]))
	}
	return tw.Flush()
}

func sortedConfigKeys(config runtime.ConfigDocument) []string {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func formatConfigValue(value any) string {
	switch typed := value.(type) {
	case []string:
		return strings.Join(typed, ",")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, value := range typed {
			parts = append(parts, fmt.Sprint(value))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(typed)
	}
}
