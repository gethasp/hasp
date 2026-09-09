package brokerops

import (
	"fmt"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// AuthorizationError describes a denied operation without exposing its token or values.
type AuthorizationError struct {
	Reason         string                  `json:"reason"`
	Requirement    store.AccessRequirement `json:"requirement"`
	Operation      store.Operation         `json:"operation,omitempty"`
	ItemName       string                  `json:"item_name,omitempty"`
	OnceConsumed   bool                    `json:"once_consumed"`
	requiresPrompt bool
}

func NewAuthorizationError(handle *store.Handle, req store.AccessRequest, decision store.AccessDecision) *AuthorizationError {
	e := &AuthorizationError{Reason: decision.Reason, Requirement: decision.RequiredAction(), Operation: req.Operation, ItemName: req.ItemName, requiresPrompt: decision.RequiresPrompt}
	if handle == nil {
		return e
	}
	e.OnceConsumed = handle.OnceGrantConsumed(req, e.Requirement)
	return e
}

func (e *AuthorizationError) Error() string {
	label := "access denied"
	if e.requiresPrompt {
		label = "unsupported approval path"
	}
	switch e.Requirement {
	case store.AccessRequirementProjectLease, store.AccessRequirementProjectAndConvenience:
		label = "project lease required"
	case store.AccessRequirementSecretGrant:
		label = "secret approval required"
	case store.AccessRequirementConvenience:
		label = "convenience approval required"
	case store.AccessRequirementWriteGrant:
		label = "capture write grant required"
	case store.AccessRequirementUnsupported:
		label = "unsupported approval path"
	}
	message := fmt.Sprintf("%s for %s: %s", label, e.Operation, e.Reason)
	if e.ItemName != "" {
		message += fmt.Sprintf(" (item %q)", e.ItemName)
	}
	if e.OnceConsumed {
		message += "; the matching once grant was already consumed"
	}
	return message
}

func (e *AuthorizationError) GrantField() string {
	switch e.Requirement {
	case store.AccessRequirementProjectLease, store.AccessRequirementProjectAndConvenience:
		return "grant_project"
	case store.AccessRequirementSecretGrant:
		return "grant_secret"
	case store.AccessRequirementConvenience:
		return "grant_convenience"
	case store.AccessRequirementWriteGrant:
		return "grant_write"
	default:
		return ""
	}
}

func (e *AuthorizationError) CLIHint() string {
	field := e.GrantField()
	if field == "" {
		return "inspect the operation and item policy with `hasp secret show <NAME>`"
	}
	flag := "--" + strings.ReplaceAll(field, "_", "-")
	if field == "grant_write" {
		return "retry the same command with " + flag + " after approving creation of the item"
	}
	if e.OnceConsumed && field == "grant_convenience" {
		return "the once approval for this destination and reference set was used; if another workspace write is approved, retry with --grant-convenience window --grant-window 15m"
	}
	if e.OnceConsumed {
		return "for a new once approval, start a fresh agent session (or omit --session-token for a standalone CLI call), then retry with " + flag + " once; a consumed once grant cannot be reissued in the same session"
	}
	return "retry the same command with " + flag + " once after approving this operation"
}

func (e *AuthorizationError) MCPHint() string {
	field := e.GrantField()
	if field == "" || field == "grant_convenience" {
		return "inspect the operation and its policy through the CLI"
	}
	if field == "grant_write" {
		return "retry with grant_write=true after approving creation of the item"
	}
	if e.OnceConsumed {
		return "start a fresh agent MCP session and retry with " + field + "=once for a new one-use approval; reconnecting does not replay the command"
	}
	return "retry the same tool call with " + field + "=once after approving this operation; session or window scopes require an explicit broader approval"
}
