package app

import (
	"context"
	"io"
	"sort"
	"strings"
)

// warnBareEnvRefs emits a single deprecation line on stderr for every
// bare-form (non-@-prefixed) reference in the given mapping. The canonical
// form is NAME=@REF; bare NAME=REF continues to resolve during the
// deprecation window. command/flag are surfaced in the warning so the user
// knows which call site to update.
//
// hasp-y78u: routes through emitDeprecationWarning so --quiet and
// HASP_NO_DEPRECATION suppress the line.
func warnBareEnvRefs(ctx context.Context, stderr io.Writer, mapping mappingFlag, command string, flag string) {
	if stderr == nil || len(mapping) == 0 {
		return
	}
	bare := make([]string, 0, len(mapping))
	for name, ref := range mapping {
		if !strings.HasPrefix(strings.TrimSpace(ref), "@") {
			bare = append(bare, name)
		}
	}
	if len(bare) == 0 {
		return
	}
	sort.Strings(bare)
	emitDeprecationWarning(ctx, stderr,
		"[hasp] %s %s NAME=REF without an '@' prefix is deprecated; use NAME=@REF (affected: %s)\n",
		command, flag, strings.Join(bare, ", "),
	)
}
