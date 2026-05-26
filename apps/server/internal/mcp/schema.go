package mcp

import "github.com/gethasp/hasp/apps/server/internal/store"

func catalog() []tool {
	tools := []tool{
		{Name: "hasp_list", Description: "List project-scoped references and safe named refs. Prefer the named_reference form for brokered use; do not retrieve raw secret values.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
		})},
		{Name: "hasp_check", Description: "Scan the project for managed secret leaks", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"grant_project": grantSchema(),
		})},
		{Name: "hasp_targets", Description: "List sanitized manifest targets for a project. Returns target names, refs, delivery kinds, and prerequisite status, never values or repo-controlled command argv.", InputSchema: schema(map[string]any{
			"project_root": stringSchema("Bound project root"),
		})},
		{Name: "hasp_target_explain", Description: "Explain one manifest target using sanitized refs, delivery kinds, destination names, and manifest identity. Never returns secret values or repo-controlled command argv.", InputSchema: schema(map[string]any{
			"project_root": stringSchema("Bound project root"),
			"target":       stringSchema("Manifest target name"),
		}, "target")},
		{Name: "hasp_run", Description: "Run a command with brokered secret access. Prefer this over raw secret inspection. Reference values may be opaque repo aliases like secret_01 or named refs like @OPENAI_API_KEY.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
			"grant_secret":  grantSchema(),
			"target":        stringSchema("Optional manifest target to expand into env/file refs. Command argv is still explicit."),
			"env":           mapSchema("Environment variable to reference mappings. Values may be opaque repo refs like secret_01 or named refs like @OPENAI_API_KEY."),
			"command":       stringArraySchema("Command argv"),
		}, "command")},
		{Name: "hasp_inject", Description: "Run a command with safe file injection. Prefer this over fetching raw file secrets into agent context. Reference values may be opaque repo aliases like file_01 or named refs like @GOOGLE_APPLICATION_CREDENTIALS.", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
			"grant_secret":  grantSchema(),
			"target":        stringSchema("Optional manifest target to expand into file refs. Command argv is still explicit."),
			"files":         mapSchema("Environment variable to file reference mappings. Values may be opaque repo refs like file_01 or named refs like @GOOGLE_APPLICATION_CREDENTIALS."),
			"command":       stringArraySchema("Command argv"),
		}, "command")},
	}
	if mcpUnsafeSecretWriteToolsEnabled() {
		tools = append(tools,
			tool{Name: "hasp_capture", Description: "Capture a new unmanaged candidate secret into HASP", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Bound project root"),
				"session_token": stringSchema("Optional daemon-backed session token"),
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantSchema(),
				"grant_secret":  grantSchema(),
				"grant_write":   boolSchema("Explicit audited write-grant acknowledgement for new secrets"),
				"name":          stringSchema("Secret name"),
				"kind":          stringSchema("Secret kind"),
				"value":         stringSchema("Candidate secret value"),
				"bind":          boolSchema("Bind the captured secret into the project"),
			}, "name", "value")},
			tool{Name: "hasp_secret_add", Description: "Add a secret to the personal vault and optionally expose it in the current repo", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Optional repo root to expose into"),
				"session_token": stringSchema("Optional daemon-backed session token"),
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantSchema(),
				"grant_secret":  grantSchema(),
				"grant_write":   boolSchema("Explicit audited write-grant acknowledgement for new secrets"),
				"name":          stringSchema("Secret name"),
				"value":         stringSchema("Secret value"),
				"kind":          stringSchema("Secret kind"),
				"expose":        boolSchema("Expose the secret in the repo when project_root is set"),
				"on_conflict":   stringSchema("Collision policy: error, replace, or skip"),
			}, "name", "value")},
			tool{Name: "hasp_secret_update", Description: "Update an existing secret and optionally keep it exposed in the current repo", InputSchema: schema(map[string]any{
				"project_root":  stringSchema("Optional repo root to keep exposed in"),
				"session_token": stringSchema("Optional daemon-backed session token"),
				"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
				"grant_project": grantSchema(),
				"grant_secret":  grantSchema(),
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
			"session_token": stringSchema("Optional daemon-backed session token; omitted callers get or reuse a local MCP session"),
			"grant_project": grantSchema(),
			"host_label":    stringSchema("Optional caller label"),
			"name":          stringSchema("Secret name"),
		}, "name")},
		tool{Name: "hasp_redact", Description: "Redact managed values from supplied text", InputSchema: schema(map[string]any{
			"text": stringSchema("Text to redact"),
		}, "text")},
	)
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

func grantSchema() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Audited grant choice",
		"enum":        []string{string(store.GrantOnce), string(store.GrantSession), string(store.GrantWindow)},
	}
}
