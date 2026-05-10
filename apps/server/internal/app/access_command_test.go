package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAccessMatrixCommandMatchesRuntimeResponse(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)
	if err := runWithStarter(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := openVaultHandleFn(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	item, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("secret"), store.ItemMetadata{})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertAppConsumer(store.AppConsumer{
		Name:        "ci-runner",
		ProjectRoot: t.TempDir(),
		Command:     []string{"true"},
		Bindings:    []store.AppBinding{{SecretName: "API_TOKEN", Delivery: store.AppDeliveryEnv, Target: "API_TOKEN"}},
	}); err != nil {
		t.Fatalf("upsert consumer: %v", err)
	}
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "matrix-lease",
		TTLSeconds:   300,
		ConsumerName: "ci-runner",
	}); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "matrix-secret-lease",
		TTLSeconds:   300,
		ConsumerName: "ci-runner",
	}); err != nil {
		t.Fatalf("open second session: %v", err)
	}
	rpcReply, err := client.AccessMatrix(context.Background(), runtime.AccessMatrixRequest{Consumer: "ci-runner"})
	if err != nil {
		t.Fatalf("runtime matrix: %v", err)
	}
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"access", "matrix", "--consumer", "ci-runner", "--json"}, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
		t.Fatalf("access matrix command: %v", err)
	}
	var cliReply runtime.AccessMatrixResponse
	if err := json.Unmarshal(out.Bytes(), &cliReply); err != nil {
		t.Fatalf("decode cli matrix: %v\n%s", err, out.String())
	}
	if len(cliReply.Grants) != 1 || cliReply.Grants[0].SecretID != item.ID || cliReply.Grants[0].Source != "policy" {
		t.Fatalf("cli matrix = %+v", cliReply)
	}
	// The CLI is a thin transport adapter: for identical filters, JSON must
	// match the runtime response byte-for-byte after decoding.
	if !accessMatrixEqual(cliReply, rpcReply) {
		t.Fatalf("cli/runtime matrix mismatch:\ncli %+v\nrpc %+v", cliReply, rpcReply)
	}
	var human bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"access", "matrix", "--consumer", "ci-runner"}, bytes.NewBuffer(nil), &human, io.Discard, starter); err != nil {
		t.Fatalf("access matrix human: %v", err)
	}
	if !bytes.Contains(human.Bytes(), []byte("CONSUMER")) || !bytes.Contains(human.Bytes(), []byte("ci-runner")) {
		t.Fatalf("human matrix output missing table data: %s", human.String())
	}
}

func accessMatrixEqual(a, b runtime.AccessMatrixResponse) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aj, bj)
}
