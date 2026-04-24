package app

import (
	"fmt"
	"io"
	"strings"
)

var bootstrapPrintConfigKnownFormats = []string{"stdio-json", "cursor-json", "codex-toml", "claude-json"}

func bootstrapPrintConfigCommand(args []string, stdout io.Writer) error {
	target := ""
	format := "stdio-json"

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return fmt.Errorf("print-config: --format requires a value")
			}
			format = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			if target == "" {
				target = arg
			}
			continue
		}
	}

	if target != "generic-compatible" {
		return fmt.Errorf("print-config: unknown target")
	}

	known := false
	for _, f := range bootstrapPrintConfigKnownFormats {
		if f == format {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("print-config: unsupported format %q", format)
	}

	snippets := agentGenericPrintConfig()
	snippet := snippets[format]
	_, err := fmt.Fprint(stdout, snippet)
	return err
}
