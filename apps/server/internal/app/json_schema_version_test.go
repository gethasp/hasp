package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// hasp-1dg1: every JSON-mode response carries a top-level "_schema" field so
// downstream consumers can detect breaking shape changes without parsing
// arbitrary text. The renderer injects the field in writeJSONResponse before
// emitting the payload.
func TestRenderJSONOrHumanInjectsSchemaVersion(t *testing.T) {
	cases := []struct {
		name    string
		payload any
	}{
		{"map", map[string]any{"status": "ok"}},
		{"empty_map", map[string]any{}},
		{"struct", struct {
			Name string `json:"name"`
		}{Name: "hasp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderJSONOrHuman(context.Background(), &buf, true, tc.payload, func(io.Writer) error {
				t.Fatal("human renderer must not fire when --json is set")
				return nil
			}); err != nil {
				t.Fatalf("renderJSONOrHuman: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
				t.Fatalf("decode: %v\nraw: %s", err, buf.String())
			}
			schema, ok := decoded["_schema"]
			if !ok {
				t.Fatalf("expected _schema field, got: %v", decoded)
			}
			if got, _ := schema.(float64); got != float64(jsonSchemaVersion) {
				t.Fatalf("expected _schema=%d, got %v", jsonSchemaVersion, schema)
			}
		})
	}
}

// TestVersionAndDoctorJSONCarrySchemaVersion locks in that the central
// renderer (renderJSONOrHuman) and the bypass call sites (doctor) both emit
// the schema field — the contract is "every JSON-mode response", not just
// the central path.
func TestVersionAndDoctorJSONCarrySchemaVersion(t *testing.T) {
	lockAppSeams(t)

	var versionBuf bytes.Buffer
	if err := versionCommand(context.Background(), []string{"--json"}, &versionBuf); err != nil {
		t.Fatalf("versionCommand --json: %v", err)
	}
	if !strings.Contains(versionBuf.String(), `"_schema":1`) {
		t.Fatalf("version --json missing _schema:1 stamp: %s", versionBuf.String())
	}

	var doctorBuf bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--json"}, bytes.NewBuffer(nil), &doctorBuf, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("doctor --json: %v", err)
	}
	if !strings.Contains(doctorBuf.String(), `"_schema":1`) {
		t.Fatalf("doctor --json missing _schema:1 stamp: %s", doctorBuf.String())
	}
}

// TestRenderNotRunningJSONCarriesSchemaVersion: bypass JSON path on the
// daemon-not-running short-circuit also stamps schema.
func TestRenderNotRunningJSONCarriesSchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	if err := renderNotRunning(&buf, true); err != nil {
		t.Fatalf("renderNotRunning: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v\nraw: %s", err, buf.String())
	}
	if got, _ := decoded["_schema"].(float64); got != float64(jsonSchemaVersion) {
		t.Fatalf("expected _schema=%d, got %v", jsonSchemaVersion, decoded["_schema"])
	}
	if running, _ := decoded["running"].(bool); running {
		t.Fatalf("expected running=false, got %v", decoded["running"])
	}
}
