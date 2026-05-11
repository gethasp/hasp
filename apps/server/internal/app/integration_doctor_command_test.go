package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestDoctorTargetJSONMatchesDaemonDoctor(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	starter := newDaemonTestStarter(t)

	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--target", "mcp", "--profile", "claude-code", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatalf("doctor --target: %v", err)
	}
	var cliReply runtime.IntegrationDoctorResponse
	if err := json.Unmarshal(out.Bytes(), &cliReply); err != nil {
		t.Fatalf("decode CLI doctor: %v\n%s", err, out.String())
	}

	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	rpcReply, err := client.DoctorIntegration(context.Background(), runtime.IntegrationDoctorRPCRequest{TargetID: "mcp", ProfileID: "claude-code"})
	_ = client.Close()
	if err != nil {
		t.Fatalf("rpc doctor: %v", err)
	}
	cliReply.DurationMS = 0
	rpcReply.DurationMS = 0
	cliReply.CheckedAt = rpcReply.CheckedAt
	if !reflect.DeepEqual(cliReply, rpcReply) {
		t.Fatalf("CLI/RPC doctor mismatch\ncli=%+v\nrpc=%+v", cliReply, rpcReply)
	}
	if cliReply.RuntimeProbe {
		t.Fatalf("integration doctor must not claim runtime probing for metadata-only checks: %+v", cliReply)
	}
	if strings.Contains(out.String(), "do-not-expose") || strings.Contains(out.String(), "HASP_MASTER_PASSWORD") {
		t.Fatalf("doctor output leaked forbidden token: %s", out.String())
	}
}

func TestDoctorWithoutTargetRetainsExistingJSONShape(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	starter := newDaemonTestStarter(t)

	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"doctor", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatalf("doctor --json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode doctor output: %v\n%s", err, out.String())
	}
	for _, forbidden := range []string{"target_id", "checks", "duration_ms", "profile_id"} {
		if _, ok := payload[forbidden]; ok {
			t.Fatalf("default doctor JSON gained scoped key %q: %+v", forbidden, payload)
		}
	}
	for _, required := range []string{"daemon_running", "vault_state", "binding_state", "_schema"} {
		if _, ok := payload[required]; !ok {
			t.Fatalf("default doctor JSON missing %q: %+v", required, payload)
		}
	}
}
