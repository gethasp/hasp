package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestLeaseListAndRevokeCommandsUseLeaseSchema(t *testing.T) {
	lockAppSeams(t)
	starter := newDaemonTestStarter(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	first, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "lease-cli-a",
		ProjectRoot:  t.TempDir(),
		TTLSeconds:   300,
		ConsumerName: "ci-runner",
	})
	if err != nil {
		t.Fatalf("open first session: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "lease-cli-b",
		ProjectRoot:  t.TempDir(),
		TTLSeconds:   300,
		ConsumerName: "ci-runner",
	}); err != nil {
		t.Fatalf("open second session: %v", err)
	}
	if _, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "lease-cli-c",
		ProjectRoot:  t.TempDir(),
		TTLSeconds:   300,
		ConsumerName: "human-cli",
	}); err != nil {
		t.Fatalf("open other session: %v", err)
	}

	var listOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"lease", "list", "--consumer", "ci-runner", "--json"}, bytes.NewBuffer(nil), &listOut, io.Discard, starter); err != nil {
		t.Fatalf("lease list --json: %v", err)
	}
	var list runtime.ListLeasesResponse
	if err := json.Unmarshal(listOut.Bytes(), &list); err != nil {
		t.Fatalf("decode lease list: %v\n%s", err, listOut.String())
	}
	if list.Total != 2 || len(list.Leases) != 2 {
		t.Fatalf("lease list = %+v, want two ci-runner leases", list)
	}
	for _, key := range []string{`"_schema"`, `"leases"`, `"total"`, `"has_more"`} {
		if !bytes.Contains(listOut.Bytes(), []byte(key)) {
			t.Fatalf("lease list JSON missing %s: %s", key, listOut.String())
		}
	}

	var revokeOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"lease", "revoke", first.SessionID, "--reason", "test", "--json"}, bytes.NewBuffer(nil), &revokeOut, io.Discard, starter); err != nil {
		t.Fatalf("lease revoke: %v", err)
	}
	var revoked runtime.RevokeLeaseResponse
	if err := json.Unmarshal(revokeOut.Bytes(), &revoked); err != nil {
		t.Fatalf("decode revoke reply: %v\n%s", err, revokeOut.String())
	}
	if !revoked.Revoked || revoked.RevokedCount != 1 {
		t.Fatalf("revoke reply = %+v, want one revoked lease", revoked)
	}

	listOut.Reset()
	if err := runWithStarter(context.Background(), []string{"lease", "list", "--status", "revoked", "--json"}, bytes.NewBuffer(nil), &listOut, io.Discard, starter); err != nil {
		t.Fatalf("lease list revoked: %v", err)
	}
	if err := json.Unmarshal(listOut.Bytes(), &list); err != nil {
		t.Fatalf("decode revoked lease list: %v\n%s", err, listOut.String())
	}
	if list.Total != 1 || list.Leases[0].ID != first.SessionID || list.Leases[0].Status != "revoked" {
		t.Fatalf("revoked lease list = %+v", list)
	}

	var bulkOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"lease", "revoke", "--all-for-consumer", "ci-runner", "--json"}, bytes.NewBuffer(nil), &bulkOut, io.Discard, starter); err != nil {
		t.Fatalf("lease revoke --all-for-consumer: %v", err)
	}
	if err := json.Unmarshal(bulkOut.Bytes(), &revoked); err != nil {
		t.Fatalf("decode bulk revoke reply: %v\n%s", err, bulkOut.String())
	}
	if revoked.RevokedCount != 1 {
		t.Fatalf("bulk revoke count = %d, want remaining one ci-runner lease", revoked.RevokedCount)
	}
}
