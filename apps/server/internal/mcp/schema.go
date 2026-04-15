package mcp

import "github.com/gethasp/hasp/apps/server/internal/store"

func catalog() []tool {
	return []tool{
		{Name: "hasp_list", Description: "List project-scoped references", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
		})},
		{Name: "hasp_check", Description: "Scan the project for managed secret leaks", InputSchema: schema(map[string]any{
			"project_root": stringSchema("Bound project root"),
		})},
		{Name: "hasp_run", Description: "Run a command with brokered secret access", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
			"grant_secret":  grantSchema(),
			"env":           mapSchema("Environment variable to reference mappings"),
			"command":       stringArraySchema("Command argv"),
		}, "command")},
		{Name: "hasp_inject", Description: "Run a command with safe file injection", InputSchema: schema(map[string]any{
			"project_root":  stringSchema("Bound project root"),
			"session_token": stringSchema("Optional daemon-backed session token"),
			"host_label":    stringSchema("Optional caller label for auto-opened sessions"),
			"grant_project": grantSchema(),
			"grant_secret":  grantSchema(),
			"files":         mapSchema("Environment variable to file reference mappings"),
			"command":       stringArraySchema("Command argv"),
		}, "files", "command")},
		{Name: "hasp_capture", Description: "Capture a new unmanaged candidate secret into HASP", InputSchema: schema(map[string]any{
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
		{Name: "hasp_redact", Description: "Redact managed values from supplied text", InputSchema: schema(map[string]any{
			"text": stringSchema("Text to redact"),
		}, "text")},
	}
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
