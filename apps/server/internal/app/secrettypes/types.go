// Package secrettypes holds the shared shapes and constants that the secret
// CLI surfaces (which will move out to internal/app/secretops/ in Stage 2d)
// and the rendering / dispatch code that stays in package app must both
// reference. Keeping them here breaks the import cycle that would otherwise
// form between secretops and app's cli_output / runtime_commands / setup
// surfaces. hasp-fjvf (Stage 2b of hasp-mgz5).
package secrettypes

import "github.com/gethasp/hasp/apps/server/internal/store"

// Env variable names used by the agent-safe plaintext policy and by the
// runtime / agent consumer plumbing. Centralising them here means callers in
// either package can read or write the same key without re-declaring it.
const (
	EnvAgentSafeMode    = "HASP_AGENT_SAFE_MODE"
	EnvSessionToken     = "HASP_SESSION_TOKEN"
	EnvAgentConsumer    = "HASP_AGENT_CONSUMER"
	EnvAgentProjectRoot = "HASP_AGENT_PROJECT_ROOT"
)

// TimeRFC3339 is the layout that the CLI uses for every operator-visible
// timestamp (secret list, session list, doctor, etc.).
const TimeRFC3339 = "2006-01-02T15:04:05Z07:00"

// MetadataView is the operator-facing JSON shape for a single secret entry.
// Used by `secret get`, `secret list`, and `secret search` rendering.
type MetadataView struct {
	Name           string               `json:"name"`
	NamedReference string               `json:"named_reference,omitempty"`
	Kind           store.ItemKind       `json:"kind"`
	CreatedAt      string               `json:"created_at"`
	UpdatedAt      string               `json:"updated_at"`
	Exposures      []store.ItemExposure `json:"exposures"`
}

// MutationView is the operator-facing JSON shape for any secret-mutating
// command (add / update / delete / expose / hide / rotate). Outcome carries
// the verb-specific status string (e.g. "added", "skipped", "deleted").
type MutationView struct {
	Name           string               `json:"name"`
	NamedReference string               `json:"named_reference,omitempty"`
	Kind           store.ItemKind       `json:"kind,omitempty"`
	Outcome        string               `json:"outcome"`
	ProjectRoot    string               `json:"project_root,omitempty"`
	Reference      string               `json:"reference,omitempty"`
	Exposures      []store.ItemExposure `json:"exposures,omitempty"`
}
