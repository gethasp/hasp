package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// globalFlags holds the values of the top-level flags HASP recognises before a
// subcommand name. Each subcommand may opt in to honouring these by reading
// globalFlagsFromContext.
//
// --no-pager was removed because no pager seam exists in the codebase. If a
// pager is added in the future, restore noPager and wire it to shouldPage.
type globalFlags struct {
	json    bool
	yes     bool
	quiet   bool
	verbose bool
	debug   bool
	version bool
	noColor bool
}

type globalFlagsCtxKey struct{}

func contextWithGlobalFlags(parent context.Context, gf globalFlags) context.Context {
	return context.WithValue(parent, globalFlagsCtxKey{}, gf)
}

func globalFlagsFromContext(ctx context.Context) globalFlags {
	if ctx == nil {
		return globalFlags{}
	}
	if v, ok := ctx.Value(globalFlagsCtxKey{}).(globalFlags); ok {
		return v
	}
	return globalFlags{}
}

// parseGlobalFlags scans the entire argv (up to any "--" terminator) and
// extracts recognised global flags wherever they appear — before, between, or
// after the subcommand name and its positional args.  This lets the user write
// either `hasp --no-color doctor --json` or `hasp doctor --json --no-color`.
//
// Rules:
//   - A "--" token terminates global-flag scanning: everything from "--"
//     onward is included verbatim in rest (the subcommand may rely on it).
//   - A flag token that appears BEFORE the first positional (subcommand) and
//     is not a recognised global flag is an error, so top-level typos are
//     caught early.
//   - A flag token that appears AFTER the first positional and is not a
//     recognised global flag is left in rest for the subcommand parser.
func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	var gf globalFlags
	var rest []string
	seenPositional := false

	for i := 0; i < len(args); i++ {
		token := args[i]

		// "--" terminates global-flag scanning; append everything from here.
		if token == "--" {
			rest = append(rest, args[i:]...)
			break
		}

		// Positional (non-flag) token: always goes to rest.
		if !strings.HasPrefix(token, "-") {
			seenPositional = true
			rest = append(rest, token)
			continue
		}

		// Flag token: check if it is a recognised global flag.
		name, value, hasValue := splitGlobalFlag(token)
		switch name {
		case "--json", "-json":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.json = set
		case "--yes", "-yes", "-y":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.yes = set
		case "--quiet", "-quiet", "-q":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.quiet = set
		case "--verbose", "-verbose", "-v":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.verbose = set
		case "--debug", "-debug":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.debug = set
		case "--version", "-version", "-V":
			if seenPositional {
				rest = append(rest, token)
				continue
			}
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.version = set
		case "--no-color", "-no-color":
			set, err := parseGlobalBool(name, value, hasValue)
			if err != nil {
				return globalFlags{}, nil, err
			}
			gf.noColor = set
		case "--help", "-h":
			seenPositional = true
			rest = append(rest, token)
		default:
			// Unknown flag before the subcommand: error (catches top-level typos).
			// Unknown flag after the subcommand: pass through to the subcommand parser.
			if !seenPositional {
				return globalFlags{}, nil, fmt.Errorf("unknown global flag %q (place subcommand-specific flags after the command name)", token)
			}
			rest = append(rest, token)
		}
	}
	return gf, rest, nil
}

func splitGlobalFlag(token string) (name string, value string, hasValue bool) {
	if eq := strings.IndexByte(token, '='); eq >= 0 {
		return token[:eq], token[eq+1:], true
	}
	return token, "", false
}

func parseGlobalBool(name, value string, hasValue bool) (bool, error) {
	if !hasValue {
		return true, nil
	}
	v, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid value for %s: %q", name, value)
	}
	return v, nil
}
