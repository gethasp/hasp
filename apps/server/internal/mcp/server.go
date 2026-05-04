package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

type response struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      any        `json:"id"`
	Result  any        `json:"result,omitempty"`
	Error   *respError `json:"error,omitempty"`
}

type respError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

const currentProtocolVersion = "2025-06-18"

var supportedProtocolVersions = map[string]struct{}{
	currentProtocolVersion: {},
	"2026-04-13":           {},
}

func Serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	dec := json.NewDecoder(stdin)
	enc := json.NewEncoder(stdout)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		// Ignore notifications. Codex sends `notifications/initialized`, and
		// replying to a notification produces unsolicited traffic on the MCP
		// stream that stricter clients reject.
		if req.ID == nil {
			continue
		}
		resp := dispatch(ctx, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
}

func dispatch(ctx context.Context, req request) response {
	switch req.Method {
	case "initialize":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"protocolVersion": negotiateProtocolVersion(req.Params),
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "hasp", "version": runtime.VersionString()},
		}}
	case "tools/list":
		return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": catalog()}}
	case "tools/call":
		var call toolCall
		if err := json.Unmarshal(req.Params, &call); err != nil {
			return fail(req.ID, -32602, "invalid tool call params")
		}
		result, err := callTool(ctx, call)
		if err != nil {
			return fail(req.ID, -32000, err.Error())
		}
		return response{JSONRPC: "2.0", ID: req.ID, Result: result}
	default:
		return fail(req.ID, -32601, "method not found")
	}
}

func fail(id any, code int, message string) response {
	return response{JSONRPC: "2.0", ID: id, Error: &respError{Code: code, Message: message}}
}

func negotiateProtocolVersion(params json.RawMessage) string {
	if len(bytes.TrimSpace(params)) == 0 {
		return currentProtocolVersion
	}
	var init initializeParams
	if err := json.Unmarshal(params, &init); err != nil {
		return currentProtocolVersion
	}
	if _, ok := supportedProtocolVersions[init.ProtocolVersion]; ok {
		return init.ProtocolVersion
	}
	return currentProtocolVersion
}
