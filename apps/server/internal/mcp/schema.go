package mcp

import "github.com/gethasp/hasp/apps/server/internal/store"

func catalog() []tool {
	optionalSessionToken := stringSchema("Optional daemon-backed session token. Usually omit this; HASP reuses a session for this connection and canonical project root. Auto-opened sessions expire after 30 minutes; expiration or daemon restart requires fresh grants. Explicit stale tokens fail closed.")
	tools := []tool{
		{Name: "hasp_status", Description: "Verify this MCP transport is responding. This does not attest the client's sibling shell tools; run hasp agent status <agent-id> through the client's shell to check that process tree.", InputSchema: schema(map[string]any{})},
		{Name: "hasp_list", Description: "List project-scoped references and safe named refs. Prefer the named_reference form for brokered use; do not retrieve raw secret values.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": optionalSessionToken,
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantProjectSchema(),
		})},
		{Name: "hasp_check", Description: "Scan the project for managed secret leaks", InputSchema: schema(map[string]any{
			"project_root":    stringSchema("Bound project root"),
			"session_token":   optionalSessionToken,
			"grant_project":   grantProjectSchema(),
			"staged":          boolSchema("Scan the active Git index instead of working-tree files. Default false."),
			"fail_on_skipped": boolSchema("Treat skipped sources, such as oversized files, as an incomplete-scan tool error. I/O failures always return an error with partial results."),
		})},
		{Name: "hasp_targets", Description: "List sanitized manifest targets for a project. Returns target names, refs, delivery kinds, and prerequisite status, never values or repo-controlled command argv.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": optionalSessionToken,
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantProjectSchema(),
		})},
		{Name: "hasp_target_explain", Description: "Explain one manifest target using sanitized refs, delivery kinds, destination names, and manifest identity. Never returns secret values or repo-controlled command argv.", InputSchema: schema(map[string]any{
			"project_root": stringSchema("Bound project root"),
			"target":       stringSchema("Manifest target name"),
		}, "target")},
		{Name: "hasp_run", Description: "Run a command with brokered secret access. For deployments or other long runs, use hasp_job_start so timeouts cannot lose the result. Prefer this over raw secret inspection. Reference values may be opaque repo aliases like secret_01 or named refs like @OPENAI_API_KEY.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": optionalSessionToken,
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantProjectSchema(),
			"grant_secret":  grantSecretSchema(),
			"target":        stringSchema("Optional manifest target to expand into env/file refs. Command argv is still explicit."),
			"env":           mapSchema("Environment variable to KV secret references. Use an exposed @NAME or repo alias; never a literal value."),
			"files":         mapSchema("Environment variable to secret references delivered as temporary file paths"),
			"literal_env":   mapSchema("Explicit non-secret configuration strings, preserved without expansion. Empty strings are allowed. Cannot collide with env/files or override a target."),
			"command":       stringArraySchema("Command argv"),
		}, "command")},
		{Name: "hasp_inject", Description: "Run a command with safe file injection. Prefer this over fetching raw file secrets into agent context. Reference values may be opaque repo aliases like file_01 or named refs like @GOOGLE_APPLICATION_CREDENTIALS.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": optionalSessionToken,
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantProjectSchema(),
			"grant_secret":  grantSecretSchema(),
			"target":        stringSchema("Optional manifest target to expand into file refs. Command argv is still explicit."),
			"files":         mapSchema("Environment variable to secret references delivered as temporary file paths"),
			"env":           mapSchema("Environment variable to KV secret references. Use an exposed @NAME or repo alias; never a literal value."),
			"literal_env":   mapSchema("Explicit non-secret configuration strings, preserved without expansion. Cannot collide with env/files or override a target."),
			"command":       stringArraySchema("Command argv"),
		}, "command")},
	}
	if mcpUnsafeSecretWriteToolsEnabled() {
		tools = append(tools,
			tool{Name: "hasp_capture", Description: "Capture a new unmanaged candidate secret into HASP", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Bound project root"),
				"session_token": optionalSessionToken,
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantProjectSchema(),
				"grant_secret":  grantSecretSchema(),
				"grant_write":   boolSchema("Explicit audited write-grant acknowledgement for new secrets"),
				"name":          stringSchema("Secret name"),
				"kind":          stringSchema("Secret kind"),
				"value":         stringSchema("Candidate secret value"),
				"bind":          boolSchema("Bind the captured secret into the project"),
			}, "name", "value")},
			tool{Name: "hasp_secret_add", Description: "Add a secret to the personal vault and optionally expose it in the current repo", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Optional repo root to expose into"),
				"session_token": optionalSessionToken,
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantProjectSchema(),
				"grant_secret":  grantSecretSchema(),
				"grant_write":   boolSchema("Explicit audited write-grant acknowledgement for new secrets"),
				"name":          stringSchema("Secret name"),
				"value":         stringSchema("Secret value"),
				"kind":          stringSchema("Secret kind"),
				"expose":        boolSchema("Expose the secret in the repo when project_root is set"),
				"on_conflict":   stringSchema("Collision policy: error, replace, or skip"),
			}, "name", "value")},
			tool{Name: "hasp_secret_update", Description: "Update an existing secret and optionally keep it exposed in the current repo", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Optional repo root to keep exposed in"),
				"session_token": optionalSessionToken,
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantProjectSchema(),
				"grant_secret":  grantSecretSchema(),
				"grant_write":   boolSchema("Explicit audited write-grant acknowledgement for new secrets"),
				"name":          stringSchema("Secret name"),
				"value":         stringSchema("Updated secret value"),
				"kind":          stringSchema("Secret kind"),
				"expose":        boolSchema("Expose the secret in the repo when project_root is set"),
			}, "name", "value")},
			tool{Name: "hasp_secret_delete", Description: "Delete a secret from the personal vault and invalidate repo exposures", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Repo root used for audited authorization"),
				"session_token": stringSchema("Daemon-backed session token with a persisted delete mutation grant"),
				"host_label":    stringSchema("Optional caller label"),
				"name":          stringSchema("Secret name"),
			}, "project_root", "name")},
			tool{Name: "hasp_secret_expose", Description: "Expose an existing secret in the current repo using a repo-scoped reference", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Repo root"),
				"session_token": stringSchema("Daemon-backed session token with a persisted expose mutation grant"),
				"host_label":    stringSchema("Optional caller label"),
				"name":          stringSchema("Secret name"),
			}, "project_root", "name")},
			tool{Name: "hasp_secret_hide", Description: "Remove repo visibility for a secret without deleting it from the personal vault", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Repo root"),
				"session_token": stringSchema("Daemon-backed session token with a persisted hide mutation grant"),
				"host_label":    stringSchema("Optional caller label"),
				"name":          stringSchema("Secret name"),
			}, "project_root", "name")},
		)
	}
	tools = append(tools,
		tool{Name: "hasp_secret_get", Description: "Get metadata for a secret without returning its raw value. Use this to confirm a vault secret exists and to obtain its safe named_reference for hasp_run or hasp_inject.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Optional repo root to check availability in"),
			"session_token": optionalSessionToken,
			"grant_project": grantProjectSchema(),
			"host_label":    stringSchema("Optional caller label"),
			"name":          stringSchema("Secret name"),
		}, "name")},
		tool{Name: "hasp_redact", Description: "Redact managed values from supplied text", InputSchema: schema(map[string]any{
			"text": stringSchema("Text to redact"),
		}, "text")},
	)
	tools = append(tools, tool{Name: "hasp_job_start", Description: "Start a recoverable brokered command and return its job handle promptly. Use for long runs. Generate a random request_id once and retain it; retries with the same ID return the original job and never launch again. Poll hasp_job_status for redacted progress and completion.", InputSchema: schema(map[string]any{
		"project_root": stringSchema("Bound project root"), "session_token": optionalSessionToken, "host_label": stringSchema("Caller label"),
		"grant_project": grantProjectSchema(), "grant_secret": grantSecretSchema(),
		"literal_env": mapSchema("Explicit non-secret configuration strings. Included in the job fingerprint; changes require a new request_id for new work."),
		"request_id":  stringSchema("New random 32-character hexadecimal ID for new work. Retain and reuse only for recovery of this exact command."),
		"target":      stringSchema("Optional reviewed manifest target"), "command": stringArraySchema("Explicit command argv"),
		"env": mapSchema("Environment variable to secret reference mappings"), "files": mapSchema("Environment variable to file secret reference mappings"),
	}, "request_id", "command")})
	for _, name := range []string{"hasp_job_status", "hasp_job_cancel"} {
		description := "Read bounded redacted progress and final status for an existing job. Supply its job_id, or its original request_id if the start response was lost. Offsets request only new output. Never starts a command. The handle authorizes access to this job receipt across MCP reconnects."
		if name == "hasp_job_cancel" {
			description = "Request cancellation of an existing job and its process group. Poll status until cancellation finishes. Supply job_id or its original request_id. Never starts a command."
		}
		tools = append(tools, tool{Name: name, Description: description, InputSchema: schema(map[string]any{
			"project_root": stringSchema("The job's original project root"), "session_token": optionalSessionToken,
			"job_id":        stringSchema("Handle returned by hasp_job_start; omit when supplying request_id"),
			"request_id":    stringSchema("Original start request ID, for recovery when the job_id was not received"),
			"stdout_offset": map[string]any{"type": "integer", "minimum": 0, "description": "Previous stdout_offset; omit to get the retained tail"},
			"stderr_offset": map[string]any{"type": "integer", "minimum": 0, "description": "Previous stderr_offset; omit to get the retained tail"},
		})})
	}
	return tools
}

func ToolNames() []string {
	tools := catalog()
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}

func schema(properties map[string]any, required ...string) map[string]any {
	out := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func stringSchema(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func boolSchema(description string) map[string]any {
	return map[string]any{"type": "boolean", "description": description}
}

func stringArraySchema(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": description,
		"items":       map[string]any{"type": "string"},
	}
}

func mapSchema(description string) map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          description,
		"additionalProperties": map[string]any{"type": "string"},
	}
}

func grantProjectSchema() map[string]any {
	return grantSchema("Audited project-lease grant. A fresh MCP session holds no lease, so send this on the first call against a repo; without an active lease the call fails with project_lease_required. " + grantScopeHelp)
}

func grantSecretSchema() map[string]any {
	return grantSchema("Audited grant for access to the referenced secrets. Send this when a call fails with secret_session_grant_required or access_secret_prompt_required. " + grantScopeHelp)
}

const grantScopeHelp = "Scopes: once authorizes this call only, session lasts for the rest of this MCP session, window lasts 15 minutes."

func grantSchema(description string) map[string]any {
	return map[string]any{
		"type":        "string",
		"description": description,
		"enum":        []string{string(store.GrantOnce), string(store.GrantSession), string(store.GrantWindow)},
	}
}
