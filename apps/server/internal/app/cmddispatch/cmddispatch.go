// Package cmddispatch centralises the CLI-dispatch primitives that the
// secret CLI surfaces (and other soon-to-move subpackages) need: help
// routing, JSON-vs-human output, and a narrow read of the global flag
// state. Without this seam the secretops/ handlers would have to reach
// back into package app, which app must in turn import for the
// dispatch entrypoint — the classic import cycle.
//
// Pattern: cmddispatch exports function-typed seams plus thin wrapper
// helpers. Package app registers concrete closures in init() that read
// its existing seam variables / call its package-private helpers
// dynamically, so any test mutation of those originals (e.g. tests
// that override globalFlags context wiring) flows through transparently.
// Same approach as internal/app/auditlog/ (hasp-tpsi) and
// internal/app/vaultaccess/ (hasp-da2w). hasp-0u3n (Stage 2f of hasp-mgz5).
package cmddispatch

import (
	"context"
	"io"
)

// Function-typed seams. Package app installs concrete implementations
// in its init(); calling these before registration panics.
var (
	PrintHelpTopicFn    func(w io.Writer, args []string) error
	IsHelpArgFn         func(value string) bool
	WriteJSONResponseFn func(w io.Writer, payload any) error
	RenderJSONOrHumanFn func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error
	JSONFlagFn          func(ctx context.Context) bool
	YesFlagFn           func(ctx context.Context) bool
)

// PrintHelpTopic emits the help topic for args (joined and normalised
// inside the registered implementation) to w.
func PrintHelpTopic(w io.Writer, args []string) error {
	return PrintHelpTopicFn(w, args)
}

// IsHelpArg reports whether value is one of the recognised help-flag
// spellings ("help", "-h", "--help", case-insensitive).
func IsHelpArg(value string) bool {
	return IsHelpArgFn(value)
}

// WriteJSONResponse writes payload as JSON with the top-level _schema
// version field injected when the encoded form is a JSON object.
func WriteJSONResponse(w io.Writer, payload any) error {
	return WriteJSONResponseFn(w, payload)
}

// RenderJSONOrHuman emits either the JSON encoding of payload or the
// caller-supplied human renderer. The local jsonOutput flag is ORed
// with the global --json flag read from ctx.
func RenderJSONOrHuman(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error {
	return RenderJSONOrHumanFn(ctx, stdout, jsonOutput, payload, human)
}

// JSONFlag reports whether the global --json flag is set on ctx.
func JSONFlag(ctx context.Context) bool {
	return JSONFlagFn(ctx)
}

// YesFlag reports whether the global --yes flag is set on ctx.
func YesFlag(ctx context.Context) bool {
	return YesFlagFn(ctx)
}
