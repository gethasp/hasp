package sessionops

import (
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

// cliPair constructs a [2]string label/value pair for rendering helpers.
func cliPair(label string, value string) [2]string {
	return [2]string{label, value}
}

// sessionStateBadge returns a colourised "[active]" or "[expired]" badge for
// a session view. Called by renderSessionListWithColor.
func sessionStateBadge(sv runtime.SessionView, now time.Time, opts ui.ColorOptions) string {
	if !sv.ExpiresAt.IsZero() && sv.ExpiresAt.After(now) {
		return ui.Colorize("[active]", ui.ColorOK, opts)
	}
	return ui.Colorize("[expired]", ui.ColorDeny, opts)
}
