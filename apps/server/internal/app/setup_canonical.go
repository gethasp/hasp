package app

import (
	"fmt"
	"io"
)

// hasp-v88h: hasp setup is the canonical setup surface. The legacy verbs
// hasp init, hasp bootstrap, and hasp project bind continue to work but each
// emits a single stderr line pointing at hasp setup so docs and quickstarts
// can converge on one verb.
func noteSetupCanonical(stderr io.Writer, command string) {
	if stderr == nil {
		return
	}
	fmt.Fprintf(stderr, "[hasp] %s still works; 'hasp setup' is the canonical setup surface.\n", command)
}
