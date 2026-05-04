package app

import (
	"flag"
	"fmt"
	"io"
)

// noteResolvedProjectRootIfImplicit emits a single stderr line naming the
// resolved --project-root when the user did not pass it explicitly. A user
// running 'hasp run -- mycmd' from /tmp gets a 'not a git repo' failure
// otherwise without ever seeing which path hasp used; this notice closes that
// gap. Suppressed under --json so future strict --json envelopes
// (hasp-ynci) stay clean. The forthcoming --quiet flag (hasp-2vdm) will
// extend the same gate.
func noteResolvedProjectRootIfImplicit(fs *flag.FlagSet, jsonOutput bool, resolved string, stderr io.Writer) {
	if jsonOutput || stderr == nil {
		return
	}
	if projectRootFlagWasExplicit(fs) {
		return
	}
	fmt.Fprintf(stderr, "[hasp] project-root resolved to %s\n", resolved)
}

func projectRootFlagWasExplicit(fs *flag.FlagSet) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "project-root" {
			seen = true
		}
	})
	return seen
}
