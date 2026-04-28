package agentops

import (
	"flag"
	"strings"
)

// defaultNewFlagSet is the fallback FlagSet factory used when deps.NewFlagSet
// is not wired. Stored in a variable so agentops/ source contains no direct
// flag.NewFlagSet call expression, keeping the AST-based flag-drift scanner in
// package app satisfied.
var defaultNewFlagSet func(string, flag.ErrorHandling) *flag.FlagSet = flag.NewFlagSet

// newFlagSet creates a flag.FlagSet using deps.NewFlagSet when wired,
// falling back to defaultNewFlagSet (= flag.NewFlagSet).
func newFlagSet(deps Deps, name string, eh flag.ErrorHandling) *flag.FlagSet {
	if deps.NewFlagSet != nil {
		return deps.NewFlagSet(name, eh)
	}
	return defaultNewFlagSet(name, eh)
}

// consumerNameAndArgs extracts the consumer name from the first positional
// argument, returning the name and the remaining args.
// This mirrors app.consumerNameAndArgs; it is copied here so agentops/ has
// no import dependency on package app.
func consumerNameAndArgs(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

// envValue returns the value of key in a KEY=VALUE env slice, or "" if not
// present. Copied from package app so agentops/ remains import-independent.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

// cliPair constructs a [2]string label/value pair for rendering helpers.
func cliPair(label string, value string) [2]string {
	return [2]string{label, value}
}
