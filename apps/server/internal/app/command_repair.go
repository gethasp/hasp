package app

import (
	"fmt"
	"strings"
)

// These are discovery hints, not aliases. Keep ambiguous root verbs rejected.
func commandConfusionRepair(command string) *appError {
	var replacement string
	switch command {
	case "list":
		replacement = "hasp secret list"
	case "get", "show", "read", "retrieve":
		replacement = "hasp help secret show"
	case "targets", "hasp_targets":
		replacement = "hasp project targets"
	case "hasp_list":
		replacement = "hasp project status"
	case "hasp_check":
		replacement = "hasp check-repo"
	case "hasp_run":
		replacement = "hasp help run"
	case "hasp_inject":
		replacement = "hasp help inject"
	default:
		return nil
	}
	hint := "use `" + replacement + "`"
	if strings.HasPrefix(command, "hasp_") {
		hint += "; names beginning with hasp_ are MCP tools"
	}
	return newAppError(errCodeUserInput, fmt.Sprintf("unknown command %q", command)).withHint(hint)
}
