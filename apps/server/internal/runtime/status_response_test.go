package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/accessmatrix"
	"github.com/gethasp/hasp/apps/server/internal/app/auditops"
	"github.com/gethasp/hasp/apps/server/internal/app/dashboard"
	revealcore "github.com/gethasp/hasp/apps/server/internal/app/reveal"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/jsonwire"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestStatusResponseIncludesDashboardKPIs(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	sessions := NewSessionStore()
	sessions.now = func() time.Time { return now }
	if _, err := sessions.Open("host-a", "/tmp/a", 15*time.Minute, false, ""); err != nil {
		t.Fatalf("open expiring session: %v", err)
	}
	if _, err := sessions.Open("host-b", "/tmp/b", 45*time.Minute, false, ""); err != nil {
		t.Fatalf("open later session: %v", err)
	}
	auditState := newAuditState(nil)
	auditState.MarkDegradedAt(now.Add(-time.Minute))

	reply := buildStatusResponse(paths.Paths{SocketPath: "/tmp/hasp.sock"}, now.Add(-time.Hour), sessions, auditState, dashboard.HTTPListener{Host: "127.0.0.1", Port: 49152}, 0, 0)
	if reply.ActiveSessions != 2 || reply.LeasesCount != 2 {
		t.Fatalf("session counts = active %d leases %d, want 2/2", reply.ActiveSessions, reply.LeasesCount)
	}
	if reply.Vault.State != "unlocked" || reply.Vault.LastUnlockedAt == nil || reply.Vault.IdleRelockInS != int(DefaultVaultIdleTimeout.Seconds()) {
		t.Fatalf("unexpected dashboard vault payload: %+v", reply.Vault)
	}
	if !reply.Vault.LastUnlockedAt.Equal(now) {
		t.Fatalf("last_unlocked_at = %v, want original unlock time %v", reply.Vault.LastUnlockedAt, now)
	}
	if reply.Leases.ActiveCount != 2 || reply.Leases.ExpiringSoon != 1 {
		t.Fatalf("unexpected dashboard leases payload: %+v", reply.Leases)
	}
	if reply.Daemon.HTTPListener.Port != 49152 || reply.Daemon.HTTPListener.Host != "127.0.0.1" {
		t.Fatalf("unexpected dashboard listener: %+v", reply.Daemon.HTTPListener)
	}
	if reply.ApprovalsPending != 0 {
		t.Fatalf("approvals_pending = %d, want 0", reply.ApprovalsPending)
	}
	if reply.Expiring30m != 1 {
		t.Fatalf("expiring_30m = %d, want 1", reply.Expiring30m)
	}
	if reply.AuditHealth != "degraded" {
		t.Fatalf("audit_health = %q, want degraded", reply.AuditHealth)
	}
	if !reply.AuditDegraded || reply.AuditDegradedAt == nil {
		t.Fatalf("expected legacy audit degraded fields too, got %+v", reply)
	}
}

func TestRPCStatusAndDashboardSharePayloadSource(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	sessions := NewSessionStore()
	sessions.now = func() time.Time { return now }
	if _, err := sessions.Open("host", "/tmp/project", 10*time.Minute, true, "agent"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	auditState := newAuditState(nil)
	server := &rpcServer{
		startedAt:  now.Add(-time.Hour),
		paths:      paths.Paths{HomeDir: t.TempDir(), SocketPath: "/tmp/hasp.sock"},
		sessions:   sessions,
		auditState: auditState,
	}
	broker := &brokerRPC{
		paths:      server.paths,
		startedAt:  server.startedAt,
		sessions:   sessions,
		auditState: auditState,
	}

	var rpcReply StatusResponse
	if err := broker.Status(StatusRequest{}, &rpcReply); err != nil {
		t.Fatalf("broker status: %v", err)
	}
	dashboardReply := server.statusSnapshot()
	if rpcReply.LeasesCount != dashboardReply.LeasesCount ||
		rpcReply.Expiring30m != dashboardReply.Expiring30m ||
		rpcReply.ApprovalsPending != dashboardReply.ApprovalsPending ||
		rpcReply.AuditHealth != dashboardReply.AuditHealth {
		t.Fatalf("rpc/dashboard KPI mismatch: rpc=%+v dashboard=%+v", rpcReply, dashboardReply)
	}
}

func TestHTTPDashboardReturnsStatusPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		AuditPath:        fmt.Sprintf("%s/audit.jsonl", t.TempDir()),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.sessions.now = func() time.Time { return now }
	if _, err := rpcSrv.sessions.Open("host", "/tmp/project", 10*time.Minute, false, ""); err != nil {
		t.Fatalf("open session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	signDashboardRequest(req, key, time.Now().UTC())

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read dashboard body: %v", err)
	}
	var payload dashboard.Response
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode dashboard payload: %v", err)
	}
	if payload.Leases.ActiveCount != 1 || payload.Leases.ExpiringSoon != 1 || !payload.Audit.ChainOK {
		t.Fatalf("unexpected dashboard KPIs: %+v", payload)
	}

	dashboardBody := new(bytes.Buffer)
	expected, err := rpcSrv.dashboardSnapshot()
	if err != nil {
		t.Fatalf("snapshot expected dashboard payload: %v", err)
	}
	if err := jsonwire.WriteResponse(dashboardBody, expected); err != nil {
		t.Fatalf("encode expected dashboard payload: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode dashboard body as map: %v", err)
	}
	var want map[string]any
	if err := json.Unmarshal(dashboardBody.Bytes(), &want); err != nil {
		t.Fatalf("decode expected dashboard payload: %v", err)
	}
	if got["_schema"] != float64(jsonwire.SchemaVersion) {
		t.Fatalf("expected dashboard _schema=%d, got %v", jsonwire.SchemaVersion, got["_schema"])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dashboard payload drifted from shared JSON writer:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestHTTPDashboardReturns503WhenVaultStateUnavailable(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.sessions = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	signDashboardRequest(req, key, time.Now().UTC())

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("dashboard request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("dashboard status = %d, want 503", resp.StatusCode)
	}
}

func TestHTTPLeasesListRevokeBulkAndAudit(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.audit = log
	rpcSrv.auditState = newAuditState(nil)
	broker := rpcSrv.broker()

	var first OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "runner-a", ProjectRoot: "/tmp/a", TTLSeconds: 300, ConsumerName: "ci-runner"}, &first); err != nil {
		t.Fatalf("open first session: %v", err)
	}
	var second OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "runner-b", ProjectRoot: "/tmp/b", TTLSeconds: 300, ConsumerName: "ci-runner"}, &second); err != nil {
		t.Fatalf("open second session: %v", err)
	}
	var other OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "human", ProjectRoot: "/tmp/c", TTLSeconds: 300, ConsumerName: "human-cli"}, &other); err != nil {
		t.Fatalf("open other session: %v", err)
	}
	var batchA OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "batch-a", ProjectRoot: "/tmp/d", TTLSeconds: 300, ConsumerName: "batch-ci"}, &batchA); err != nil {
		t.Fatalf("open batch a session: %v", err)
	}
	var batchB OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "batch-b", ProjectRoot: "/tmp/e", TTLSeconds: 300, ConsumerName: "batch-ci"}, &batchB); err != nil {
		t.Fatalf("open batch b session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/leases?consumer=ci-runner", httpSrv.Ports().V4), nil)
	var httpList ListLeasesResponse
	if err := json.Unmarshal(body, &httpList); err != nil {
		t.Fatalf("decode http list: %v", err)
	}
	if httpList.Total != 2 || len(httpList.Leases) != 2 {
		t.Fatalf("consumer filtered list = %+v, want exactly two ci-runner leases", httpList)
	}

	var rpcList ListLeasesResponse
	if err := broker.ListLeases(ListLeasesRequest{ConsumerID: "ci-runner"}, &rpcList); err != nil {
		t.Fatalf("rpc list leases: %v", err)
	}
	httpJSON := normalizeJSONMap(t, body)
	rpcBuf := new(bytes.Buffer)
	if err := jsonwire.WriteResponse(rpcBuf, rpcList); err != nil {
		t.Fatalf("encode rpc list: %v", err)
	}
	if rpcJSON := normalizeJSONMap(t, rpcBuf.Bytes()); !reflect.DeepEqual(httpJSON, rpcJSON) {
		t.Fatalf("http/rpc lease schema mismatch:\nhttp %#v\nrpc  %#v", httpJSON, rpcJSON)
	}

	revokeBody := []byte(`{"reason":"test"}`)
	_ = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/leases/%s/revoke", httpSrv.Ports().V4, first.SessionID), revokeBody)
	_ = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/leases/%s/revoke", httpSrv.Ports().V4, first.SessionID), revokeBody)
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/leases?status=revoked", httpSrv.Ports().V4), nil)
	var revokedList ListLeasesResponse
	if err := json.Unmarshal(body, &revokedList); err != nil {
		t.Fatalf("decode revoked list: %v", err)
	}
	if revokedList.Total != 1 || revokedList.Leases[0].ID != first.SessionID || revokedList.Leases[0].Status != "revoked" {
		t.Fatalf("revoked list after single revoke = %+v", revokedList)
	}

	selectedBody := signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/leases/bulk-revoke", httpSrv.Ports().V4), []byte(fmt.Sprintf(`{"lease_ids":[%q,%q],"reason":"selected-test"}`, batchA.SessionID, batchB.SessionID)))
	var selectedBulk RevokeLeaseResponse
	if err := json.Unmarshal(selectedBody, &selectedBulk); err != nil {
		t.Fatalf("decode selected bulk revoke: %v", err)
	}
	if selectedBulk.RevokedCount != 2 {
		t.Fatalf("selected bulk revoked %d, want two selected leases", selectedBulk.RevokedCount)
	}

	bulkBody := signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/leases/bulk-revoke", httpSrv.Ports().V4), []byte(`{"all_for_consumer":"ci-runner","reason":"bulk-test"}`))
	var bulk RevokeLeaseResponse
	if err := json.Unmarshal(bulkBody, &bulk); err != nil {
		t.Fatalf("decode bulk revoke: %v", err)
	}
	if bulk.RevokedCount != 1 {
		t.Fatalf("bulk revoked %d, want only remaining ci-runner lease; other=%s", bulk.RevokedCount, other.SessionID)
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/leases?status=active", httpSrv.Ports().V4), nil)
	var activeList ListLeasesResponse
	if err := json.Unmarshal(body, &activeList); err != nil {
		t.Fatalf("decode active list: %v", err)
	}
	if activeList.Total != 1 || activeList.Leases[0].ConsumerID != "human-cli" {
		t.Fatalf("active leases after bulk revoke = %+v", activeList)
	}

	events, err := log.Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	revokeEvents := 0
	for _, event := range events {
		if event.Details["action"] == "lease.revoke" {
			revokeEvents++
		}
	}
	if revokeEvents != 4 {
		t.Fatalf("lease revoke audit events = %d, want 4; events=%+v", revokeEvents, events)
	}
}

func TestHTTPAccessMatrixUsesSharedReadModel(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	now := time.Date(2026, 5, 10, 9, 0, 0, 0, time.UTC)
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.accessMatrixInput = func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error) {
		return accessmatrix.Input{
			AppConsumers: []store.AppConsumer{{
				Name:     "ci-runner",
				Bindings: []store.AppBinding{{SecretName: "API_TOKEN"}},
			}},
			AgentConsumers: []store.AgentConsumer{{Name: "writer", AgentID: "codex", ConfigPath: "/tmp/config"}},
			Items: []store.Item{
				{ID: "sec_api", Name: "API_TOKEN", UpdatedAt: now},
				{ID: "sec_db", Name: "DATABASE_URL", UpdatedAt: now.Add(-time.Hour)},
			},
			Now: now,
		}, nil
	}
	broker := rpcSrv.broker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/access/matrix?consumer=ci-runner&limit=1", httpSrv.Ports().V4), nil)
	var httpReply AccessMatrixResponse
	if err := json.Unmarshal(body, &httpReply); err != nil {
		t.Fatalf("decode matrix: %v\n%s", err, body)
	}
	if httpReply.Total != 1 || len(httpReply.Grants) != 1 || httpReply.Grants[0].Source != "policy" {
		t.Fatalf("http matrix = %+v, want one policy grant", httpReply)
	}
	var rpcReply AccessMatrixResponse
	if err := broker.AccessMatrix(AccessMatrixRequest{Consumer: "ci-runner", Limit: 1}, &rpcReply); err != nil {
		t.Fatalf("rpc matrix: %v", err)
	}
	rpcBuf := new(bytes.Buffer)
	if err := jsonwire.WriteResponse(rpcBuf, rpcReply); err != nil {
		t.Fatalf("encode rpc matrix: %v", err)
	}
	if got, want := normalizeJSONMap(t, body), normalizeJSONMap(t, rpcBuf.Bytes()); !reflect.DeepEqual(got, want) {
		t.Fatalf("http/rpc access matrix mismatch:\nhttp %#v\nrpc  %#v", got, want)
	}
}

func TestHTTPPolicyGetPutConflictValidationAndSSE(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		SocketPath:         "/tmp/hasp.sock",
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(home, "daemon.http.sock"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topic=policy.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/policy", httpSrv.Ports().V4)
	body := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	var initial PolicyResponse
	if err := json.Unmarshal(body, &initial); err != nil {
		t.Fatalf("decode initial policy: %v\n%s", err, body)
	}
	if initial.Schema == 0 || initial.Version != "0" || len(initial.Rules) != 0 {
		t.Fatalf("initial policy = %+v", initial)
	}

	next := PolicyDocument{Version: initial.Version, Rules: []PolicyRule{{
		ID:       "allow-ci",
		Match:    PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"},
		Decision: "allow",
		TTLS:     900,
	}}}
	nextBody, err := json.Marshal(next)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	updatedBody := signedHTTPJSONWithHeaders(t, ctx, key, http.MethodPut, baseURL, nextBody, map[string]string{"If-Match": initial.Version})
	var updated PolicyResponse
	if err := json.Unmarshal(updatedBody, &updated); err != nil {
		t.Fatalf("decode updated policy: %v\n%s", err, updatedBody)
	}
	if updated.Version == "" || updated.Version == initial.Version || updated.UpdatedBy != "http" || len(updated.Rules) != 1 {
		t.Fatalf("updated policy = %+v", updated)
	}
	waitForSSELineWithin(t, lines, "event: policy.changed", 250*time.Millisecond)
	waitForSSELineWithin(t, lines, fmt.Sprintf("data: {\"version\":%q}", updated.Version), 250*time.Millisecond)

	staleBody, staleStatus := signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodPut, baseURL, nextBody, map[string]string{"If-Match": initial.Version})
	if staleStatus != http.StatusConflict {
		t.Fatalf("stale PUT status = %d body=%s, want 409", staleStatus, staleBody)
	}
	missingPreconditionBody, missingPreconditionStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL, nextBody)
	if missingPreconditionStatus != http.StatusConflict {
		t.Fatalf("missing If-Match PUT status = %d body=%s, want 409", missingPreconditionStatus, missingPreconditionBody)
	}
	trailingBody, trailingStatus := signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodPut, baseURL, []byte(`{"version":"`+updated.Version+`","rules":[]} {}`), map[string]string{"If-Match": updated.Version})
	if trailingStatus != http.StatusBadRequest {
		t.Fatalf("trailing JSON PUT status = %d body=%s, want 400", trailingStatus, trailingBody)
	}
	conflicting := PolicyDocument{Version: updated.Version, Rules: []PolicyRule{
		{ID: "allow-ci", Match: PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"}, Decision: "allow"},
		{ID: "deny-ci", Match: PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"}, Decision: "deny"},
	}}
	conflictingBody, err := json.Marshal(conflicting)
	if err != nil {
		t.Fatalf("marshal conflicting policy: %v", err)
	}
	rejectedBody, rejectedStatus := signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodPut, baseURL, conflictingBody, map[string]string{"If-Match": updated.Version})
	if rejectedStatus != http.StatusUnprocessableEntity || !bytes.Contains(rejectedBody, []byte("ci-runner")) {
		t.Fatalf("conflicting PUT status = %d body=%s, want 422 with detail", rejectedStatus, rejectedBody)
	}
	finalBody := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	var final PolicyResponse
	if err := json.Unmarshal(finalBody, &final); err != nil {
		t.Fatalf("decode final policy: %v\n%s", err, finalBody)
	}
	if final.Version != updated.Version || len(final.Rules) != 1 {
		t.Fatalf("policy changed after rejected PUTs: %+v", final)
	}
}

func TestHTTPPolicyLockedVaultReturns423(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	home := t.TempDir()
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		SocketPath:         "/tmp/hasp.sock",
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(home, "daemon.http.sock"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/policy", httpSrv.Ports().V4)
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL, nil)
	if status != http.StatusLocked {
		t.Fatalf("locked GET status = %d body=%s, want 423", status, body)
	}
	policyBody, err := json.Marshal(PolicyDocument{Version: "0"})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	body, status = signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodPut, baseURL, policyBody, map[string]string{"If-Match": "0"})
	if status != http.StatusLocked {
		t.Fatalf("locked PUT status = %d body=%s, want 423", status, body)
	}
}

func TestHTTPConfigGetPutValidationSecretKeysAndSSE(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		SocketPath:         "/tmp/hasp.sock",
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(home, "daemon.http.sock"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topic=config.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "cccccccccccccccccccccccccccccccc")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	lines := make(chan string, 32)
	go readSSELines(eventsResp.Body, lines)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/config", httpSrv.Ports().V4)
	body := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	for _, forbidden := range []string{"hmac.secret", "master_password_hash", "license.blob", "do-not-expose"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("config response leaked forbidden token %q: %s", forbidden, body)
		}
	}
	var initial ConfigResponse
	if err := json.Unmarshal(body, &initial); err != nil {
		t.Fatalf("decode config: %v\n%s", err, body)
	}
	wantKeys := []string{
		"audit.export_format_default",
		"audit.retention_days",
		"backup.destination_path",
		"backup.last_backup_at",
		"backup.last_backup_path",
		"backup.retention_count",
		"backup.schedule",
		"clipboard.scrub_seconds",
		"integrations.disabled_targets",
		"notifications.approvals_enabled",
		"notifications.critical_consumer_ids",
		"notifications.expiring_lease_threshold_s",
		"reveal.scrub_seconds",
		"ui.differentiate_without_color",
		"ui.language",
		"ui.reduce_motion_override",
		"updates.channel",
		"vault.auto_relock_enabled",
		"vault.biometric_unlock_enabled",
		"vault.idle_relock_s",
	}
	gotKeys := make([]string, 0, len(initial.Config))
	for key := range initial.Config {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !slices.Equal(gotKeys, wantKeys) {
		t.Fatalf("config keys = %v, want %v", gotKeys, wantKeys)
	}
	if _, ok := initial.Config["vault.idle_relock_s"].(float64); !ok {
		t.Fatalf("idle_relock type = %T", initial.Config["vault.idle_relock_s"])
	}
	if _, ok := initial.Config["vault.auto_relock_enabled"].(bool); !ok {
		t.Fatalf("auto_relock type = %T", initial.Config["vault.auto_relock_enabled"])
	}
	if _, ok := initial.Config["audit.export_format_default"].(string); !ok {
		t.Fatalf("export format type = %T", initial.Config["audit.export_format_default"])
	}
	if _, ok := initial.Config["integrations.disabled_targets"].([]any); !ok {
		t.Fatalf("disabled targets type = %T", initial.Config["integrations.disabled_targets"])
	}

	updates := []struct {
		key   string
		value string
		want  any
	}{
		{"audit.retention_days", `{"value":120}`, float64(120)},
		{"vault.auto_relock_enabled", `{"value":false}`, false},
		{"ui.reduce_motion_override", `{"value":"on"}`, "on"},
		{"integrations.disabled_targets", `{"value":["shell-hook","mcp"]}`, []any{"mcp", "shell-hook"}},
		{"backup.schedule", `{"value":"daily"}`, "daily"},
		{"backup.retention_count", `{"value":3}`, float64(3)},
		{"backup.destination_path", `{"value":"/tmp/HASP.hasp-backup"}`, "/tmp/HASP.hasp-backup"},
	}
	for _, tc := range updates {
		putURL := baseURL + "/" + url.PathEscape(tc.key)
		replyBody := signedHTTPJSON(t, ctx, key, http.MethodPut, putURL, []byte(tc.value))
		var valueReply ConfigValueResponse
		if err := json.Unmarshal(replyBody, &valueReply); err != nil {
			t.Fatalf("decode config value reply for %s: %v\n%s", tc.key, err, replyBody)
		}
		if valueReply.Key != tc.key {
			t.Fatalf("reply key = %q, want %q", valueReply.Key, tc.key)
		}
		waitForSSELineWithin(t, lines, "event: config.changed", 250*time.Millisecond)
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	var updated ConfigResponse
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("decode updated config: %v\n%s", err, body)
	}
	for _, tc := range updates {
		if !reflect.DeepEqual(updated.Config[tc.key], tc.want) {
			t.Fatalf("updated config[%s] = %#v, want %#v", tc.key, updated.Config[tc.key], tc.want)
		}
	}
	before := normalizeJSONMap(t, body)
	badBody, badStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/reveal.scrub_seconds", []byte(`{"value":"slow"}`))
	if badStatus != http.StatusUnprocessableEntity || !bytes.Contains(badBody, []byte("reveal.scrub_seconds")) {
		t.Fatalf("invalid config status = %d body=%s, want 422 with key", badStatus, badBody)
	}
	unknownTargetBody, unknownTargetStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/integrations.disabled_targets", []byte(`{"value":["unknown-target"]}`))
	if unknownTargetStatus != http.StatusUnprocessableEntity || !bytes.Contains(unknownTargetBody, []byte("integrations.disabled_targets")) {
		t.Fatalf("unknown target status = %d body=%s, want 422 with key", unknownTargetStatus, unknownTargetBody)
	}
	trailingPathBody, trailingPathStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/reveal.scrub_seconds/", []byte(`{"value":45}`))
	if trailingPathStatus != http.StatusNotFound {
		t.Fatalf("trailing path status = %d body=%s, want 404", trailingPathStatus, trailingPathBody)
	}
	encodedSlashBody, encodedSlashStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/hmac%2Fsecret", []byte(`{"value":"do-not-expose"}`))
	if encodedSlashStatus != http.StatusNotFound || bytes.Contains(encodedSlashBody, []byte("do-not-expose")) {
		t.Fatalf("encoded slash status = %d body=%s, want 404 without value", encodedSlashStatus, encodedSlashBody)
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	if !reflect.DeepEqual(normalizeJSONMap(t, body), before) {
		t.Fatalf("invalid config PUT changed state\nbefore=%#v\nafter=%#v", before, normalizeJSONMap(t, body))
	}
	for _, secretKey := range []string{"hmac.secret", "master_password_hash", "license.blob"} {
		secretBody, secretStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/"+url.PathEscape(secretKey), []byte(`{"value":"do-not-expose"}`))
		if secretStatus != http.StatusNotFound || bytes.Contains(secretBody, []byte("do-not-expose")) {
			t.Fatalf("secret key %s status=%d body=%s, want 404 without value", secretKey, secretStatus, secretBody)
		}
	}
}

func TestHTTPConfigLockedVaultReturns423(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	home := t.TempDir()
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		SocketPath:         "/tmp/hasp.sock",
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(home, "daemon.http.sock"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/config", httpSrv.Ports().V4)
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL, nil)
	if status != http.StatusLocked {
		t.Fatalf("locked GET status = %d body=%s, want 423", status, body)
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPut, baseURL+"/reveal.scrub_seconds", []byte(`{"value":45}`))
	if status != http.StatusLocked {
		t.Fatalf("locked PUT status = %d body=%s, want 423", status, body)
	}
}

func TestHTTPIntegrationsListProfilesDoctorAndSSE(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	home := t.TempDir()
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          home,
		AuditPath:        filepath.Join(home, "audit.jsonl"),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topic=integrations.changed,integrations.profiles.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "dddddddddddddddddddddddddddddddd")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/integrations", httpSrv.Ports().V4)
	body := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	for _, forbidden := range []string{"do-not-expose", "HASP_MASTER_PASSWORD", "hmac.secret"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("integrations response leaked forbidden token %q: %s", forbidden, body)
		}
	}
	var list IntegrationListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode integrations: %v\n%s", err, body)
	}
	ids := make([]string, 0, len(list.Integrations))
	for _, integration := range list.Integrations {
		ids = append(ids, integration.ID)
		if integration.Kind == "" || integration.Status == "" || integration.LastCheckedAt.IsZero() {
			t.Fatalf("incomplete integration entry: %+v", integration)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"env-injection", "mcp", "shell-hook"}) {
		t.Fatalf("integration ids = %v", ids)
	}

	profileBody := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL+"/mcp/profiles", nil)
	var profileReply IntegrationProfilesResponse
	if err := json.Unmarshal(profileBody, &profileReply); err != nil {
		t.Fatalf("decode profiles: %v\n%s", err, profileBody)
	}
	if len(profileReply.Profiles) == 0 || profileReply.Profiles[0].ID == "" || profileReply.Profiles[0].TargetPattern == "" {
		t.Fatalf("profiles reply = %+v", profileReply)
	}
	doctorBody := signedHTTPJSON(t, ctx, key, http.MethodPost, baseURL+"/shell-hook/doctor", []byte(`{}`))
	var doctorReply IntegrationDoctorResponse
	if err := json.Unmarshal(doctorBody, &doctorReply); err != nil {
		t.Fatalf("decode doctor: %v\n%s", err, doctorBody)
	}
	if !doctorReply.OK || doctorReply.RuntimeProbe || doctorReply.TargetID != "shell-hook" || doctorReply.DurationMS >= 2000 {
		t.Fatalf("doctor reply = %+v", doctorReply)
	}
	waitForSSELineWithin(t, lines, "event: integrations.changed", 250*time.Millisecond)
	doctorProfileBody := signedHTTPJSON(t, ctx, key, http.MethodPost, baseURL+"/mcp/doctor", []byte(`{"profile_id":"claude-code"}`))
	var doctorProfileReply IntegrationDoctorResponse
	if err := json.Unmarshal(doctorProfileBody, &doctorProfileReply); err != nil {
		t.Fatalf("decode profile doctor: %v\n%s", err, doctorProfileBody)
	}
	if !doctorProfileReply.OK || doctorProfileReply.RuntimeProbe || doctorProfileReply.TargetID != "mcp" || doctorProfileReply.ProfileID != "claude-code" {
		t.Fatalf("profile doctor reply = %+v", doctorProfileReply)
	}

	createBody := signedHTTPJSON(t, ctx, key, http.MethodPost, baseURL+"/profiles", []byte(`{"target_id":"mcp","id":"custom-agent","name":"Custom Agent","target_pattern":"hasp agent mcp custom-agent","scope":"agent"}`))
	var created IntegrationProfileMutationResponse
	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatalf("decode created profile: %v\n%s", err, createBody)
	}
	if created.Profile.ID != "custom-agent" || created.Profile.TargetID != "mcp" || created.Profile.Version == "" || !created.Profile.Managed {
		t.Fatalf("created profile = %+v", created.Profile)
	}
	waitForSSELine(t, lines, "event: integrations.profiles.changed")
	waitForSSELine(t, lines, `data: {"target_id":"mcp","profile_id":"custom-agent","action":"create"}`)
	catalogBody := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL+"/profiles", nil)
	var catalog IntegrationProfilesResponse
	if err := json.Unmarshal(catalogBody, &catalog); err != nil {
		t.Fatalf("decode profile catalog: %v\n%s", err, catalogBody)
	}
	if !slices.ContainsFunc(catalog.Profiles, func(profile IntegrationProfile) bool {
		return profile.ID == "custom-agent" && profile.TargetID == "mcp"
	}) {
		t.Fatalf("catalog missing custom profile: %+v", catalog)
	}
	updateBody := signedHTTPJSONWithHeaders(t, ctx, key, http.MethodPut, baseURL+"/mcp/profiles/custom-agent", []byte(`{"name":"Custom Agent 2","target_pattern":"hasp agent mcp custom-agent-v2","scope":"agent","enabled":false}`), map[string]string{"If-Match": created.Profile.Version})
	var updated IntegrationProfileMutationResponse
	if err := json.Unmarshal(updateBody, &updated); err != nil {
		t.Fatalf("decode updated profile: %v\n%s", err, updateBody)
	}
	if updated.Profile.Name != "Custom Agent 2" || updated.Profile.Enabled || updated.Profile.Version == created.Profile.Version {
		t.Fatalf("updated profile = %+v", updated.Profile)
	}
	staleBody, staleStatus := signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodPut, baseURL+"/mcp/profiles/custom-agent", []byte(`{"name":"Stale","target_pattern":"stale","scope":"agent"}`), map[string]string{"If-Match": created.Profile.Version})
	if staleStatus != http.StatusPreconditionFailed {
		t.Fatalf("stale update status=%d body=%s, want 412", staleStatus, staleBody)
	}
	deleteBody, deleteStatus := signedHTTPJSONStatusWithHeaders(t, ctx, key, http.MethodDelete, baseURL+"/mcp/profiles/custom-agent", nil, map[string]string{"If-Match": updated.Profile.Version})
	if deleteStatus != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", deleteStatus, deleteBody)
	}
	events, err := audit.NewForPaths(rpcSrv.paths).Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if !hasIntegrationProfileAudit(events, "integration.profile.delete", "custom-agent") {
		t.Fatalf("missing profile delete audit event: %+v", events)
	}

	badProfileBody, badProfileStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL+"/mcp/doctor", []byte(`{"profile_id":"missing-profile"}`))
	if badProfileStatus != http.StatusNotFound || bytes.Contains(badProfileBody, []byte("do-not-expose")) {
		t.Fatalf("bad profile status=%d body=%s, want 404 without secret echo", badProfileStatus, badProfileBody)
	}
	unknownFieldBody, unknownFieldStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL+"/mcp/doctor", []byte(`{"profile_id":"claude-code","extra":true}`))
	if unknownFieldStatus != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s, want 400", unknownFieldStatus, unknownFieldBody)
	}
	trailingJSONBody, trailingJSONStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL+"/mcp/doctor", []byte(`{"profile_id":"claude-code"} {}`))
	if trailingJSONStatus != http.StatusBadRequest {
		t.Fatalf("trailing JSON status=%d body=%s, want 400", trailingJSONStatus, trailingJSONBody)
	}
	unknownTargetBody, unknownTargetStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL+"/missing/profiles", nil)
	if unknownTargetStatus != http.StatusNotFound {
		t.Fatalf("unknown target status=%d body=%s, want 404", unknownTargetStatus, unknownTargetBody)
	}
	badPathBody, badPathStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL+"/mcp/profiles/", nil)
	if badPathStatus != http.StatusNotFound {
		t.Fatalf("bad path status=%d body=%s, want 404", badPathStatus, badPathBody)
	}
	encodedSlashBody, encodedSlashStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL+"/mcp%2Fbad/profiles", nil)
	if encodedSlashStatus != http.StatusNotFound {
		t.Fatalf("encoded slash status=%d body=%s, want 404", encodedSlashStatus, encodedSlashBody)
	}
}

func TestHTTPIntegrationsDisabledTargetsAreEnforced(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		SocketPath:         "/tmp/hasp.sock",
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(home, "daemon.http.sock"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.SetConfigValue("integrations.disabled_targets", []any{"mcp"}, "test"); err != nil {
		t.Fatalf("set disabled integrations: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/integrations", httpSrv.Ports().V4)
	body := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	var list IntegrationListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode integrations: %v\n%s", err, body)
	}
	for _, integration := range list.Integrations {
		if integration.ID == "mcp" {
			t.Fatalf("disabled integration was listed: %+v", list.Integrations)
		}
	}
	profileBody, profileStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, baseURL+"/mcp/profiles", nil)
	if profileStatus != http.StatusNotFound {
		t.Fatalf("disabled profiles status=%d body=%s, want 404", profileStatus, profileBody)
	}
	doctorBody, doctorStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL+"/mcp/doctor", []byte(`{}`))
	if doctorStatus != http.StatusNotFound {
		t.Fatalf("disabled doctor status=%d body=%s, want 404", doctorStatus, doctorBody)
	}
}

func TestAccessMatrixRequestFromHTTPParsesFilters(t *testing.T) {
	req, err := http.NewRequest(
		http.MethodGet,
		"/v1/access/matrix?range=24h&consumer=ci-runner&secret=prod%2Fdb%2Fpassword&scope=read&source=policy&has_active_lease=true&cursor=20&limit=10000",
		nil,
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	parsed, err := accessMatrixRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("parse access matrix request: %v", err)
	}
	if parsed.Range != "24h" || parsed.Consumer != "ci-runner" || parsed.Secret != "prod/db/password" || parsed.Scope != "read" || parsed.Source != "policy" || parsed.Cursor != "20" || parsed.Limit != 10000 {
		t.Fatalf("parsed request = %+v", parsed)
	}
	if parsed.HasActiveLease == nil || !*parsed.HasActiveLease {
		t.Fatalf("has_active_lease = %v, want true", parsed.HasActiveLease)
	}
	for _, target := range []string{
		"/v1/access/matrix?limit=-1",
		"/v1/access/matrix?limit=nope",
		"/v1/access/matrix?has_active_lease=maybe",
	} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("new bad request: %v", err)
		}
		if _, err := accessMatrixRequestFromHTTP(req); err == nil {
			t.Fatalf("accessMatrixRequestFromHTTP(%q) succeeded, want error", target)
		}
	}
}

func TestHTTPSecretsListReturnsMetadataOnly(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:          home,
		StatePath:        filepath.Join(home, "vault.json"),
		AuditPath:        filepath.Join(home, "audit.jsonl"),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: filepath.Join(home, "daemon.http.port"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	item, err := handle.UpsertItem("prod/db/password", store.ItemKindKV, []byte("do-not-emit"), store.ItemMetadata{Tags: []string{"prod"}})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	if _, err := rpcSrv.audit.Append(audit.EventRead, "test", map[string]any{
		"action":    "secret.reveal",
		"item_id":   item.ID,
		"item_name": item.Name,
	}); err != nil {
		t.Fatalf("append reveal audit: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/secrets", httpSrv.Ports().V4), nil)
	if bytes.Contains(body, []byte("do-not-emit")) {
		t.Fatalf("secrets metadata leaked value: %s", body)
	}
	var reply SecretsListResponse
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode secrets list: %v\n%s", err, body)
	}
	if len(reply.Secrets) != 1 || reply.Secrets[0].Name != "password" || reply.Secrets[0].Path != "prod/db" || reply.Secrets[0].Ref != "prod/db/password" || reply.Secrets[0].LastRevealed == "" || reply.Secrets[0].Tags[0] != "prod" {
		t.Fatalf("secrets list = %+v", reply)
	}
}

func TestHTTPApprovalsListDecideGrantDenyAndSSE(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.audit = log
	rpcSrv.auditState = newAuditState(nil)
	first, err := rpcSrv.approvals.Queue(QueueApprovalInput{SecretID: "prod/db/password", RequesterConsumerID: "ci-runner", RequestedScope: "window", RequestedTTLS: 900})
	if err != nil {
		t.Fatalf("queue first approval: %v", err)
	}
	second, err := rpcSrv.approvals.Queue(QueueApprovalInput{SecretID: "prod/api/token", RequesterConsumerID: "human-cli", RequestedScope: "session", RequestedTTLS: 300})
	if err != nil {
		t.Fatalf("queue second approval: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topic=approvals.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", eventsResp.StatusCode)
	}
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/approvals?status=pending", httpSrv.Ports().V4), nil)
	if bytes.Contains(body, []byte(`"decision"`)) {
		t.Fatalf("pending approval list should omit undecided decision field: %s", string(body))
	}
	var list ListApprovalsResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode approvals list: %v", err)
	}
	if list.PendingCount != 2 || len(list.Approvals) != 2 || list.OldestPendingAgeS < 0 {
		t.Fatalf("approval list = %+v, want two pending", list)
	}
	status := rpcSrv.statusSnapshot()
	if status.ApprovalsPending != 2 || status.Approvals.PendingCount != 2 {
		t.Fatalf("status approvals pending = legacy %d nested %+v, want 2", status.ApprovalsPending, status.Approvals)
	}

	detailBody := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/approvals/%s", httpSrv.Ports().V4, first.ID), nil)
	var detail ApprovalDetailResponse
	if err := json.Unmarshal(detailBody, &detail); err != nil {
		t.Fatalf("decode approval detail: %v", err)
	}
	if detail.Approval.ID != first.ID || detail.RequesterVerifier == "" || len(detail.ConsumerHistory) == 0 {
		t.Fatalf("approval detail = %+v, want selected approval with verifier and consumer history", detail)
	}
	var unlockReply OpenSessionResponse
	if err := rpcSrv.broker().OpenSession(OpenSessionRequest{HostLabel: "operator", ProjectRoot: t.TempDir(), TTLSeconds: 300, ConsumerName: "maintainer"}, &unlockReply); err != nil {
		t.Fatalf("unlock vault before approval grant: %v", err)
	}

	rejectedBody, rejectedStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/approvals/%s/decide?decision=grant&granted_ttl_s=120&scope=window", httpSrv.Ports().V4, first.ID), nil)
	if rejectedStatus != http.StatusBadRequest {
		t.Fatalf("grant without hold/auth status = %d body=%s, want 400", rejectedStatus, rejectedBody)
	}

	body = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/approvals/%s/decide?decision=grant&granted_ttl_s=120&scope=window&auth_method=device-owner&hold_duration_ms=1500", httpSrv.Ports().V4, first.ID), nil)
	var grantReply DecideApprovalResponse
	if err := json.Unmarshal(body, &grantReply); err != nil {
		t.Fatalf("decode grant reply: %v", err)
	}
	if grantReply.Approval.Status != "granted" || grantReply.LeaseID == "" {
		t.Fatalf("grant reply = %+v, want granted with lease", grantReply)
	}
	var leases ListLeasesResponse
	var listLeasesReply ListLeasesResponse
	if err := rpcSrv.broker().ListLeases(ListLeasesRequest{}, &listLeasesReply); err != nil {
		t.Fatalf("list leases after grant: %v", err)
	}
	leases = listLeasesReply
	var grantedLease Lease
	for _, lease := range leases.Leases {
		if lease.ID == grantReply.LeaseID {
			grantedLease = lease
			break
		}
	}
	if grantedLease.ID == "" || grantedLease.SecretID != "prod/db/password" || grantedLease.Scope != "window" {
		t.Fatalf("approval grant lease = %+v, want secret_id and scope preserved", grantedLease)
	}
	waitForSSELine(t, lines, fmt.Sprintf(`data: {"approval_id":%q,"status":"granted"}`, first.ID))

	denyBody := []byte(`{"decision":"deny","reason":"not now"}`)
	body = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/approvals/%s/decide", httpSrv.Ports().V4, second.ID), denyBody)
	var denyReply DecideApprovalResponse
	if err := json.Unmarshal(body, &denyReply); err != nil {
		t.Fatalf("decode deny reply: %v", err)
	}
	if denyReply.Approval.Status != "denied" || denyReply.LeaseID != "" {
		t.Fatalf("deny reply = %+v, want denied without lease", denyReply)
	}
	waitForSSELine(t, lines, fmt.Sprintf(`data: {"approval_id":%q,"status":"denied"}`, second.ID))

	events, err := log.Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	decisionEvents := 0
	denyEvents := 0
	for _, event := range events {
		if event.Details["action"] == "approval.decide" {
			decisionEvents++
			if event.Details["decision"] == "deny" && event.Type == audit.EventDeny {
				denyEvents++
			}
		}
	}
	if decisionEvents != 2 {
		t.Fatalf("approval decision audit events = %d, want 2; events=%+v", decisionEvents, events)
	}
	if denyEvents != 1 {
		t.Fatalf("deny decision audit events = %d, want 1 deny-typed row; events=%+v", denyEvents, events)
	}
}

func TestApprovalQueuePublishesPendingSSE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})

	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topics=approvals.changed,dashboard.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "cccccccccccccccccccccccccccccccc")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", eventsResp.StatusCode)
	}
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	approval, err := rpcSrv.approvals.Queue(QueueApprovalInput{
		SecretID:            "prod/db/password",
		RequesterConsumerID: "ci-runner",
		RequestedScope:      "window",
		RequestedTTLS:       900,
	})
	if err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	waitForSSELine(t, lines, "event: approvals.changed")
	waitForSSELine(t, lines, fmt.Sprintf(`data: {"approval_id":"%s","status":"pending"}`, approval.ID))
	waitForSSELine(t, lines, "event: dashboard.changed")
}

func TestConcurrentApprovalGrantDoesNotLeaveOrphanLease(t *testing.T) {
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.auditState = newAuditState(nil)
	rpcSrv.audit, _ = audit.New()
	approval, err := rpcSrv.approvals.Queue(QueueApprovalInput{
		SecretID:            "prod/db/password",
		RequesterConsumerID: "ci-runner",
		RequestedScope:      "window",
		RequestedTTLS:       120,
	})
	if err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	broker := rpcSrv.broker()
	var unlockReply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "operator", ProjectRoot: t.TempDir(), TTLSeconds: 300, ConsumerName: "maintainer"}, &unlockReply); err != nil {
		t.Fatalf("unlock vault before concurrent grants: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var reply DecideApprovalResponse
			_ = broker.DecideApproval(DecideApprovalRequest{
				ApprovalID:     approval.ID,
				Decision:       "grant",
				GrantedTTLS:    120,
				Scope:          "window",
				AuthMethod:     "device-owner",
				HoldDurationMS: 1500,
			}, &reply)
		}()
	}
	wg.Wait()
	var leases ListLeasesResponse
	if err := broker.ListLeases(ListLeasesRequest{Status: "active"}, &leases); err != nil {
		t.Fatalf("list leases: %v", err)
	}
	approvalLeaseCount := 0
	for _, lease := range leases.Leases {
		if lease.SecretID == "prod/db/password" && lease.ConsumerID == "ci-runner" {
			approvalLeaseCount++
		}
	}
	if approvalLeaseCount != 1 {
		t.Fatalf("approval leases after concurrent grants = %d in %+v, want exactly one", approvalLeaseCount, leases)
	}
}

func TestApprovalGrantRejectedWhenVaultLocked(t *testing.T) {
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.auditState = newAuditState(nil)
	rpcSrv.audit, _ = audit.New()
	broker := rpcSrv.broker()
	var unlockReply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{HostLabel: "operator", ProjectRoot: t.TempDir(), TTLSeconds: 300, ConsumerName: "maintainer"}, &unlockReply); err != nil {
		t.Fatalf("unlock vault: %v", err)
	}
	approval, err := rpcSrv.approvals.Queue(QueueApprovalInput{
		SecretID:            "prod/db/password",
		RequesterConsumerID: "ci-runner",
		RequestedScope:      "window",
		RequestedTTLS:       120,
	})
	if err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	var lockReply LockVaultResponse
	if err := broker.LockVault(LockVaultRequest{Cause: "manual"}, &lockReply); err != nil {
		t.Fatalf("lock vault: %v", err)
	}
	var grantReply DecideApprovalResponse
	err = broker.DecideApproval(DecideApprovalRequest{
		ApprovalID:     approval.ID,
		Decision:       "grant",
		GrantedTTLS:    120,
		Scope:          "window",
		AuthMethod:     "device-owner",
		HoldDurationMS: 1500,
	}, &grantReply)
	if !errors.Is(err, errVaultLocked) {
		t.Fatalf("grant while locked error = %v, want errVaultLocked", err)
	}
	var approvalsReply ListApprovalsResponse
	if err := broker.ListApprovals(ListApprovalsRequest{Status: "pending"}, &approvalsReply); err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(approvalsReply.Approvals) != 1 || approvalsReply.Approvals[0].ID != approval.ID {
		t.Fatalf("approval should remain pending after locked grant: %+v", approvalsReply)
	}
	var leases ListLeasesResponse
	if err := broker.ListLeases(ListLeasesRequest{Status: "active"}, &leases); err != nil {
		t.Fatalf("list active leases: %v", err)
	}
	if leases.Total != 0 {
		t.Fatalf("active leases after locked grant = %+v, want none", leases)
	}
}

func TestHTTPAuditListVerifyAndCommandCenterTopics(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	auditKey := []byte("fedcba9876543210fedcba9876543210")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	if _, err := log.Append(audit.EventApprove, "daemon", map[string]any{"action": "session.open", "session_id": "s-1"}); err != nil {
		t.Fatalf("append first audit row: %v", err)
	}
	if _, err := log.Append(audit.EventDeny, "daemon", map[string]any{"action": "lease.revoke", "lease_id": "lease-1"}); err != nil {
		t.Fatalf("append second audit row: %v", err)
	}
	log = log.WithKey(auditKey)
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.audit = log
	rpcSrv.auditState = newAuditState(nil)
	if _, err := rpcSrv.sessions.Open("host", "/tmp/project", 10*time.Minute, false, "agent"); err != nil {
		t.Fatalf("open session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/audit?limit=1", httpSrv.Ports().V4), nil)
	var auditList AuditListResponse
	if err := json.Unmarshal(body, &auditList); err != nil {
		t.Fatalf("decode audit list: %v", err)
	}
	if len(auditList.Entries) != 1 || auditList.Entries[0].Action != "lease.revoke" || auditList.Entries[0].Target != "lease-1" || auditList.Entries[0].Details == "" || auditList.Entries[0].Hash == "" {
		t.Fatalf("audit list newest entry = %+v, want lease revoke target", auditList)
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/audit?limit=100000", httpSrv.Ports().V4), nil)
	if err := json.Unmarshal(body, &auditList); err != nil {
		t.Fatalf("decode large audit list: %v", err)
	}
	if len(auditList.Entries) != 2 {
		t.Fatalf("large audit list entries = %d, want 2", len(auditList.Entries))
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard", httpSrv.Ports().V4), nil)
	var beforeVerify dashboard.Response
	if err := json.Unmarshal(body, &beforeVerify); err != nil {
		t.Fatalf("decode dashboard before verify: %v", err)
	}
	if beforeVerify.Audit.LastVerifiedAt != nil {
		t.Fatalf("last_verified_at before verify = %v, want absent", beforeVerify.Audit.LastVerifiedAt)
	}

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topics=audit.changed,dashboard.changed,leases.changed,access.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", eventsResp.StatusCode)
	}
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	body = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/audit/verify", httpSrv.Ports().V4), nil)
	var verify AuditVerifyResponse
	if err := json.Unmarshal(body, &verify); err != nil {
		t.Fatalf("decode audit verify: %v", err)
	}
	if !verify.OK || !verify.ChainOK || verify.CheckedCount < 2 || verify.TotalEntries < 2 || verify.LastVerifiedAt == nil {
		t.Fatalf("audit verify = %+v, want ok with checked rows", verify)
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/audit/verify", httpSrv.Ports().V4), nil)
	if err := json.Unmarshal(body, &verify); err != nil {
		t.Fatalf("decode audit verify GET: %v", err)
	}
	if !verify.ChainOK {
		t.Fatalf("audit verify GET = %+v, want ok", verify)
	}
	waitForSSELine(t, lines, "event: audit.changed")
	waitForSSELine(t, lines, "event: dashboard.changed")
	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var expectedExport bytes.Buffer
	if _, err := auditops.ExportNDJSON(&expectedExport, events, auditops.ExportOptions{}, key); err != nil {
		t.Fatalf("expected export: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/audit/export?format=ndjson", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new export request: %v", err)
	}
	signRequestWithNonce(req, key, nil, time.Now().UTC(), "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("export request: %v", err)
	}
	exportBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d body=%s", resp.StatusCode, exportBody)
	}
	if !bytes.Equal(exportBody, expectedExport.Bytes()) {
		t.Fatalf("export mismatch\nhttp=%s\nwant=%s", exportBody, expectedExport.Bytes())
	}
	body = signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard/audit", httpSrv.Ports().V4), nil)
	var auditTile dashboard.Audit
	if err := json.Unmarshal(body, &auditTile); err != nil {
		t.Fatalf("decode dashboard audit tile: %v", err)
	}
	if !auditTile.ChainOK || auditTile.LastVerifiedAt == nil {
		t.Fatalf("audit tile after verify = %+v, want ok with real last_verified_at", auditTile)
	}

	lockBody := []byte(`{"cause":"manual"}`)
	_ = signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/lock", httpSrv.Ports().V4), lockBody)
	waitForSSELine(t, lines, "event: leases.changed")
	waitForSSELine(t, lines, "event: access.changed")
	waitForSSELine(t, lines, "event: dashboard.changed")
}

func TestAuditVerifyFailureMarksDashboardDegradedAndPublishesTopics(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	t.Setenv("HASP_HOME", home)
	log, err := audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(audit.EventApprove, "daemon", map[string]any{"action": "session.open"}); err != nil {
		t.Fatalf("append audit row: %v", err)
	}
	auditPath := filepath.Join(home, "audit.jsonl")
	if err := os.WriteFile(auditPath, append(mustReadFile(t, auditPath), []byte("{bad-json\n")...), 0o600); err != nil {
		t.Fatalf("corrupt audit log: %v", err)
	}
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          home,
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})
	rpcSrv.audit = log
	rpcSrv.auditState = newAuditState(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topics=audit.changed,dashboard.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "cccccccccccccccccccccccccccccccc")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/audit/verify", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new verify request: %v", err)
	}
	signRequestWithNonce(req, key, nil, time.Now().UTC(), "dddddddddddddddddddddddddddddddd")
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	out, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read verify response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d, want 200 body=%s", resp.StatusCode, out)
	}
	var verify AuditVerifyResponse
	if err := json.Unmarshal(out, &verify); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if verify.ChainOK || verify.FirstCorruptionAt == nil {
		t.Fatalf("verify response = %+v, want corrupt with first corruption", verify)
	}
	waitForSSELine(t, lines, "event: audit.changed")
	waitForSSELine(t, lines, "event: dashboard.changed")

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard/audit", httpSrv.Ports().V4), nil)
	var auditTile dashboard.Audit
	if err := json.Unmarshal(body, &auditTile); err != nil {
		t.Fatalf("decode dashboard audit tile: %v", err)
	}
	if auditTile.ChainOK {
		t.Fatalf("audit tile after failed verify = %+v, want degraded", auditTile)
	}
}

func TestAuditVerifySnapshotCachesForThirtySeconds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HASP_HOME", home)
	log, err := audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(audit.EventApprove, "daemon", map[string]any{"action": "session.open"}); err != nil {
		t.Fatalf("append audit row: %v", err)
	}
	rpcSrv := newRPCServer(paths.Paths{HomeDir: home})
	rpcSrv.audit = log
	rpcSrv.auditState = newAuditState(nil)
	first, err := rpcSrv.auditVerifySnapshot(false)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if !first.ChainOK || first.LastVerifiedAt == nil {
		t.Fatalf("first verify = %+v, want ok with timestamp", first)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), append(mustReadFile(t, filepath.Join(home, "audit.jsonl")), []byte("{bad-json\n")...), 0o600); err != nil {
		t.Fatalf("corrupt audit log: %v", err)
	}
	second, err := rpcSrv.auditVerifySnapshot(false)
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if !second.ChainOK || second.LastVerifiedAt == nil || !second.LastVerifiedAt.Equal(*first.LastVerifiedAt) {
		t.Fatalf("second verify = %+v, want cached first response %+v", second, first)
	}
	forced, err := rpcSrv.auditVerifySnapshot(true)
	if err != nil {
		t.Fatalf("forced verify: %v", err)
	}
	if forced.ChainOK || forced.FirstCorruptionAt == nil {
		t.Fatalf("forced verify = %+v, want corruption despite warm cache", forced)
	}
	rpcSrv.auditVerifyCachedAt = time.Now().UTC().Add(-31 * time.Second)
	third, err := rpcSrv.auditVerifySnapshot(false)
	if err != nil {
		t.Fatalf("third verify: %v", err)
	}
	if third.ChainOK || third.FirstCorruptionAt == nil {
		t.Fatalf("third verify = %+v, want cache expired and corruption reported", third)
	}
}

func TestRuntimeEventHubReplaysSinceLastEventID(t *testing.T) {
	hub := newRuntimeEventHub()
	hub.publish("dashboard.changed", `{"n":1}`)
	hub.publish("leases.changed", `{"n":2}`)
	hub.publish("audit.changed", `{"n":3}`)

	replayed := hub.replaySince("1")
	if len(replayed) != 2 || replayed[0].Name != "leases.changed" || replayed[1].Name != "audit.changed" {
		t.Fatalf("replayed events = %+v, want events after id 1", replayed)
	}
	if got := hub.replaySince("not-an-id"); len(got) != 0 {
		t.Fatalf("replay invalid id = %+v, want none", got)
	}
}

func TestRuntimeEventHubClosesSlowSubscriberOnOverflow(t *testing.T) {
	hub := newRuntimeEventHub()
	sub := hub.subscribe()
	for i := 0; i < 9; i++ {
		hub.publish("approvals.changed", fmt.Sprintf(`{"n":%d}`, i))
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-sub:
			if !ok {
				hub.unsubscribe(sub)
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for slow subscriber channel to close")
		}
	}
}

func TestRuntimeHTTPServerSwiftDaemonClientSmokeCoversDashboardAndEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	oldRestartDaemonProcess := restartDaemonProcess
	restartCalled := make(chan struct{}, 1)
	restartDaemonProcess = func() {
		select {
		case restartCalled <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		restartDaemonProcess = oldRestartDaemonProcess
	})

	home, err := os.MkdirTemp("", "hasp-rt-*")
	if err != nil {
		t.Fatalf("create temp home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json.enc"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	rpcSrv.keyring = newHTTPTestKeyring()
	if _, err := rpcSrv.sessions.Open("host", "/tmp/project", 10*time.Minute, false, ""); err != nil {
		t.Fatalf("open session: %v", err)
	}

	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	macosPackage, err := filepath.Abs("../../../macos")
	if err != nil {
		t.Fatalf("resolve macos package: %v", err)
	}
	if _, err := os.Stat(macosPackage); errors.Is(err, os.ErrNotExist) {
		t.Skipf("macOS Swift package is not exported at %s", macosPackage)
	} else if err != nil {
		t.Fatalf("stat macos package: %v", err)
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", httpSrv.Ports().V4)
	runSwiftDaemonClientSmoke(t, ctx, macosPackage, baseURL, key)
	runSwiftDaemonClientSmokeWithEventTrigger(t, ctx, macosPackage, baseURL, key, rpcSrv, "vault.locked")
}

func TestRuntimeHTTPServerFailsClosedWhenHMACSecretMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) {
		return nil, httpapi.ErrHMACSecretNotProvisioned
	}
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            t.TempDir(),
		RuntimeDir:         filepath.Join(t.TempDir(), "runtime"),
		SocketPath:         filepath.Join(t.TempDir(), "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(t.TempDir(), "http.sock"),
		HTTPPortFilePath:   filepath.Join(t.TempDir(), "daemon.http.port"),
	})
	errCh := make(chan error, 1)
	if _, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh); err == nil ||
		!strings.Contains(err.Error(), "HMAC secret not provisioned") {
		t.Fatalf("expected HMAC secret not provisioned startup refusal, got %v", err)
	}
}

func TestHTTPVaultStatusAndAuthErrorsUseJSONEnvelope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	oldRestartDaemonProcess := restartDaemonProcess
	restartCalled := make(chan struct{}, 1)
	restartDaemonProcess = func() {
		select {
		case restartCalled <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		restartDaemonProcess = oldRestartDaemonProcess
	})

	home, err := os.MkdirTemp("", "hasp-vst-*")
	if err != nil {
		t.Fatalf("create temp home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json.enc"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	unsignedReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/status", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new unsigned request: %v", err)
	}
	unsignedResp, err := (&http.Client{Timeout: time.Second}).Do(unsignedReq)
	if err != nil {
		t.Fatalf("unsigned request: %v", err)
	}
	defer unsignedResp.Body.Close()
	if unsignedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want 401", unsignedResp.StatusCode)
	}
	var envelope map[string]any
	if err := json.NewDecoder(unsignedResp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode auth envelope: %v", err)
	}
	if envelope["_schema"] != "v1" {
		t.Fatalf("auth envelope schema = %v, want v1", envelope["_schema"])
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/status", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	signDashboardRequest(req, key, time.Now().UTC())
	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("vault status request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vault status = %d, want 200", resp.StatusCode)
	}
	var status VaultStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode vault status: %v", err)
	}
	if !status.Locked || status.State != "locked" {
		t.Fatalf("vault status = %+v, want locked", status)
	}

	restartBody := []byte(`{"reason":"operator"}`)
	restartReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/daemon/restart", httpSrv.Ports().V4), bytes.NewReader(restartBody))
	if err != nil {
		t.Fatalf("new restart request: %v", err)
	}
	restartReq.Header.Set("Content-Type", "application/json")
	signRequestWithNonce(restartReq, key, restartBody, time.Now().UTC(), "00112233445566778899aabbccddee00")
	restartResp, err := (&http.Client{Timeout: time.Second}).Do(restartReq)
	if err != nil {
		t.Fatalf("restart request: %v", err)
	}
	defer restartResp.Body.Close()
	if restartResp.StatusCode != http.StatusOK {
		t.Fatalf("restart status = %d, want 200", restartResp.StatusCode)
	}
	var restart RestartDaemonResponse
	if err := json.NewDecoder(restartResp.Body).Decode(&restart); err != nil {
		t.Fatalf("decode restart response: %v", err)
	}
	if !restart.Accepted || restart.Reason != "operator" {
		t.Fatalf("restart response = %+v, want accepted operator", restart)
	}
	select {
	case <-restartCalled:
	case <-time.After(time.Second):
		t.Fatal("restart endpoint did not trigger daemon process restart handoff")
	}
}

func TestRuntimeHTTPEventsStreamPublishesVaultLockTransitions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home, err := os.MkdirTemp("", "hasp-evt-*")
	if err != nil {
		t.Fatalf("create temp home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/events?topics=vault.locked", httpSrv.Ports().V4), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	signDashboardRequest(req, key, time.Now().UTC())
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", resp.StatusCode)
	}

	lines := make(chan string, 16)
	go readSSELines(resp.Body, lines)

	broker := &brokerRPC{
		paths:      rpcSrv.paths,
		startedAt:  rpcSrv.startedAt,
		sessions:   rpcSrv.sessions,
		audit:      rpcSrv.audit,
		auditState: rpcSrv.auditState,
		events:     rpcSrv.events,
	}
	var reply LockVaultResponse
	if err := broker.LockVault(LockVaultRequest{Cause: "manual"}, &reply); err != nil {
		t.Fatalf("lock vault: %v", err)
	}
	waitForSSELine(t, lines, "data: {\"cause\":\"manual\"}")
}

func TestHTTPVaultUnlockOpensSessionAndPublishesEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home, err := os.MkdirTemp("", "hasp-unlock-*")
	if err != nil {
		t.Fatalf("create temp home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	rpcSrv.validateVaultUnlock = func(context.Context, paths.Paths) error { return nil }

	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topics=vault.unlocked,leases.changed,dashboard.changed", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "0123456789abcdef0123456789abcdef")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	if eventsResp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d, want 200", eventsResp.StatusCode)
	}
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	rejectedBody, rejectedStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/unlock", httpSrv.Ports().V4), []byte(`{"method":"unknown"}`))
	if rejectedStatus != http.StatusBadRequest {
		t.Fatalf("unlock with unknown method status = %d body=%s, want 400", rejectedStatus, rejectedBody)
	}

	body := signedHTTPJSON(t, ctx, key, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/unlock", httpSrv.Ports().V4), []byte(`{"method":"device-owner"}`))
	var unlock UnlockVaultResponse
	if err := json.Unmarshal(body, &unlock); err != nil {
		t.Fatalf("decode unlock response: %v", err)
	}
	if !unlock.Unlocked || unlock.RemainingTTL <= 0 {
		t.Fatalf("unlock response = %+v, want unlocked with ttl", unlock)
	}

	statusBody := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/vault/status", httpSrv.Ports().V4), nil)
	var status VaultStatusResponse
	if err := json.Unmarshal(statusBody, &status); err != nil {
		t.Fatalf("decode vault status: %v", err)
	}
	if status.Locked || status.State != "unlocked" || status.RemainingTTL <= 0 {
		t.Fatalf("vault status after unlock = %+v, want unlocked with ttl", status)
	}
	leasesBody := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/leases?status=active", httpSrv.Ports().V4), nil)
	var activeLeases ListLeasesResponse
	if err := json.Unmarshal(leasesBody, &activeLeases); err != nil {
		t.Fatalf("decode active leases: %v", err)
	}
	if activeLeases.Total != 0 || len(activeLeases.Leases) != 0 {
		t.Fatalf("active leases after UI unlock = %+v, want no operator-visible leases", activeLeases)
	}
	dashboardBody := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/dashboard", httpSrv.Ports().V4), nil)
	var dashboardReply dashboard.Response
	if err := json.Unmarshal(dashboardBody, &dashboardReply); err != nil {
		t.Fatalf("decode dashboard: %v", err)
	}
	if dashboardReply.Vault.State != "unlocked" || dashboardReply.Leases.ActiveCount != 0 {
		t.Fatalf("dashboard after UI unlock = %+v, want unlocked vault and zero visible leases", dashboardReply)
	}
	waitForSSELine(t, lines, "event: vault.unlocked")
	waitForSSELine(t, lines, "event: dashboard.changed")
}

func TestHTTPVaultUnlockAcceptsMasterPasswordFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home, err := os.MkdirTemp("", "hasp-master-password-unlock-*")
	if err != nil {
		t.Fatalf("create temp home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json.enc"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	const password = "correct horse battery staple"
	if err := vaultStore.Init(ctx, password); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)

	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	unlockURL := fmt.Sprintf("http://127.0.0.1:%d/v1/vault/unlock", httpSrv.Ports().V4)
	rejectedBody, rejectedStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, unlockURL, []byte(`{"method":"master-password","master_password":"wrong password"}`))
	if rejectedStatus != http.StatusForbidden {
		t.Fatalf("wrong master password status = %d body=%s, want 403", rejectedStatus, rejectedBody)
	}

	body := signedHTTPJSON(t, ctx, key, http.MethodPost, unlockURL, []byte(`{"method":"master-password","master_password":"correct horse battery staple"}`))
	var unlock UnlockVaultResponse
	if err := json.Unmarshal(body, &unlock); err != nil {
		t.Fatalf("decode unlock response: %v", err)
	}
	if !unlock.Unlocked || unlock.RemainingTTL <= 0 {
		t.Fatalf("unlock response = %+v, want unlocked with ttl", unlock)
	}
}

func TestHTTPVaultInitCreatesVaultUnlocksAndRejectsRepeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	home := t.TempDir()
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json.enc"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	rpcSrv.keyring = newHTTPTestKeyring()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/vault/init", httpSrv.Ports().V4)
	weakBody, weakStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL, []byte(`{"master_password":"short"}`))
	if weakStatus != http.StatusUnprocessableEntity {
		t.Fatalf("weak init status=%d body=%s, want 422", weakStatus, weakBody)
	}
	body := signedHTTPJSON(t, ctx, key, http.MethodPost, baseURL, []byte(`{"master_password":"correct horse battery staple"}`))
	var initReply InitVaultResponse
	if err := json.Unmarshal(body, &initReply); err != nil {
		t.Fatalf("decode init response: %v\n%s", err, body)
	}
	if !initReply.Initialized || !initReply.Unlocked || initReply.RemainingTTL <= 0 {
		t.Fatalf("init reply = %+v", initReply)
	}
	vaultStore, err := store.NewForPaths(rpcSrv.keyring, rpcSrv.paths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := vaultStore.OpenWithPassword(ctx, "correct horse battery staple"); err != nil {
		t.Fatalf("open initialized vault: %v", err)
	}
	repeatBody, repeatStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, baseURL, []byte(`{"master_password":"correct horse battery staple"}`))
	if repeatStatus != http.StatusConflict {
		t.Fatalf("repeat init status=%d body=%s, want 409", repeatStatus, repeatBody)
	}
}

func TestHTTPVaultMasterPasswordChangeRekeysAndLocksVault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(ctx, "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	rpcSrv.validateVaultUnlock = func(context.Context, paths.Paths) error { return nil }
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	eventsURL := fmt.Sprintf("http://127.0.0.1:%d/v1/events?topic=vault.locked", httpSrv.Ports().V4)
	eventsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		t.Fatalf("new events request: %v", err)
	}
	signRequestWithNonce(eventsReq, key, nil, time.Now().UTC(), "0123456789abcdef0123456789abcdef")
	eventsResp, err := (&http.Client{}).Do(eventsReq)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer eventsResp.Body.Close()
	lines := make(chan string, 16)
	go readSSELines(eventsResp.Body, lines)

	changeURL := fmt.Sprintf("http://127.0.0.1:%d/v1/vault/master-password", httpSrv.Ports().V4)
	badBody, badStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, changeURL, []byte(`{"current_password":"wrong password","new_password":"new correct horse battery staple"}`))
	if badStatus != http.StatusForbidden {
		t.Fatalf("wrong password status = %d body=%s, want 403", badStatus, badBody)
	}
	body := signedHTTPJSON(t, ctx, key, http.MethodPost, changeURL, []byte(`{"current_password":"correct horse battery staple","new_password":"new correct horse battery staple"}`))
	var reply RotateMasterPasswordResponse
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode rekey response: %v\n%s", err, body)
	}
	if !reply.Rotated {
		t.Fatalf("rekey reply = %+v, want rotated", reply)
	}
	waitForSSELine(t, lines, "event: vault.locked")
	waitForSSELine(t, lines, "data: {\"cause\":\"master-password-change\"}")
	if _, err := vaultStore.OpenWithPassword(ctx, "correct horse battery staple"); !errors.Is(err, store.ErrInvalidPassword) {
		t.Fatalf("old password open err = %v, want ErrInvalidPassword", err)
	}
	if _, err := vaultStore.OpenWithPassword(ctx, "new correct horse battery staple"); err != nil {
		t.Fatalf("new password open: %v", err)
	}
	events, err := audit.NewForPaths(runtimePaths).Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if !hasMasterPasswordAudit(events, audit.EventDeny, "invalid_current_password") {
		t.Fatalf("missing invalid current password audit event: %+v", events)
	}
	if !hasMasterPasswordAudit(events, audit.EventApprove, "rotated") {
		t.Fatalf("missing successful master password audit event: %+v", events)
	}
}

func TestHTTPVaultMasterPasswordChangeRateLimitsBadPasswords(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(ctx, "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	changeURL := fmt.Sprintf("http://127.0.0.1:%d/v1/vault/master-password", httpSrv.Ports().V4)
	for i := 0; i < masterPasswordFailureLimit; i++ {
		body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, changeURL, []byte(`{"current_password":"wrong password","new_password":"new correct horse battery staple"}`))
		if status != http.StatusForbidden {
			t.Fatalf("attempt %d status = %d body=%s, want 403", i+1, status, body)
		}
	}
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, changeURL, []byte(`{"current_password":"wrong password","new_password":"new correct horse battery staple"}`))
	if status != http.StatusTooManyRequests {
		t.Fatalf("rate limited status = %d body=%s, want 429", status, body)
	}
	events, err := audit.NewForPaths(runtimePaths).Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if !hasMasterPasswordAudit(events, audit.EventDeny, "rate_limited") {
		t.Fatalf("missing rate-limited audit event: %+v", events)
	}
}

func TestHTTPKeyFingerprintReturnsCurrentKeyAndAuditsReveal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	rpcSrv := newRPCServer(runtimePaths)
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/daemon/http-key/fingerprint", httpSrv.Ports().V4), nil)
	var reply HTTPKeyFingerprintResponse
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode fingerprint response: %v\n%s", err, body)
	}
	want := strings.ToUpper(httpapi.HMACKeyFingerprintForKey(key))
	if reply.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", reply.Fingerprint, want)
	}
	events, err := audit.NewForPaths(runtimePaths).Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if !hasSecurityAudit(events, audit.EventApprove, httpKeyFingerprintAction, "revealed") {
		t.Fatalf("missing fingerprint reveal audit event: %+v", events)
	}
}

func hasMasterPasswordAudit(events []audit.Event, eventType string, result string) bool {
	return hasSecurityAudit(events, eventType, masterPasswordRateLimitAction, result)
}

func hasSecurityAudit(events []audit.Event, eventType string, action string, result string) bool {
	for _, event := range events {
		if event.Type != eventType || event.Details["action"] != action || event.Details["result"] != result {
			continue
		}
		if _, ok := event.Details["remote_addr"].(string); !ok {
			continue
		}
		return true
	}
	return false
}

func hasIntegrationProfileAudit(events []audit.Event, action string, profileID string) bool {
	for _, event := range events {
		if event.Details["action"] == action && event.Details["profile_id"] == profileID {
			return true
		}
	}
	return false
}

func TestMasterPasswordAuditDetailsIncludesTrustedPeerPID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/vault/master-password", nil)
	req = req.WithContext(httpapi.WithPeerPID(req.Context(), 4242))
	details := (&rpcServer{}).masterPasswordAuditDetails(req)
	if details["action"] != masterPasswordRateLimitAction {
		t.Fatalf("action = %v", details["action"])
	}
	if details["peer_pid"] != 4242 {
		t.Fatalf("peer_pid = %v, want 4242", details["peer_pid"])
	}
}

func TestHTTPBackupCreatesSignedFileUpdatesConfigAndPrunesRetention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	backupPublicKey, backupPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate backup signing key: %v", err)
	}
	t.Setenv("HASP_BACKUP_SIGNING_KEY_B64", base64.StdEncoding.EncodeToString(backupPrivateKey))
	t.Setenv("HASP_BACKUP_TRUST_ROOTS_HEX", hex.EncodeToString(backupPublicKey))

	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(ctx, "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.SetConfigValue("backup.retention_count", 1, "test"); err != nil {
		t.Fatalf("set retention: %v", err)
	}

	rpcSrv := newRPCServer(runtimePaths)
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	backupDir := filepath.Join(home, "backups")
	firstPath := filepath.Join(backupDir, "first.hasp-backup")
	backupURL := fmt.Sprintf("http://127.0.0.1:%d/v1/backup", httpSrv.Ports().V4)
	aliasURL := fmt.Sprintf("http://127.0.0.1:%d/v1/backups/export", httpSrv.Ports().V4)
	aliasBody, aliasStatus := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, aliasURL, []byte(`{"destination_path":"/tmp/missing-passphrase.hasp-backup"}`))
	if aliasStatus != http.StatusBadRequest || !bytes.Contains(aliasBody, []byte("passphrase")) {
		t.Fatalf("backup alias status=%d body=%s, want 400 passphrase error", aliasStatus, aliasBody)
	}
	body := signedHTTPJSON(t, ctx, key, http.MethodPost, backupURL, []byte(fmt.Sprintf(`{"destination_path":%q,"passphrase":"backup-passphrase"}`, firstPath)))
	var reply BackupResponse
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode backup response: %v\n%s", err, body)
	}
	if reply.Path != firstPath || reply.Checkpoint.Sequence < 0 {
		t.Fatalf("backup response = %+v", reply)
	}
	if !reply.Signature.Signed || !reply.Signature.Trusted || !reply.Signature.Required || reply.Signature.TrustRootCount != 1 || reply.Signature.SignerFingerprint == "" || reply.Signature.Error != "" {
		t.Fatalf("backup signature status = %+v", reply.Signature)
	}
	data, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var file store.BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode backup file: %v", err)
	}
	if file.Signature.Algorithm != "Ed25519" || file.Signature.Value == "" {
		t.Fatalf("missing signature: %+v", file.Signature)
	}

	secondPath := filepath.Join(backupDir, "second.hasp-backup")
	_ = signedHTTPJSON(t, ctx, key, http.MethodPost, backupURL, []byte(fmt.Sprintf(`{"destination_path":%q,"passphrase":"backup-passphrase"}`, secondPath)))
	if _, err := os.Stat(secondPath); err != nil {
		t.Fatalf("second backup missing: %v", err)
	}
	if _, err := os.Stat(firstPath); !os.IsNotExist(err) {
		t.Fatalf("first backup err = %v, want pruned", err)
	}

	configURL := fmt.Sprintf("http://127.0.0.1:%d/v1/config", httpSrv.Ports().V4)
	configBody := signedHTTPJSON(t, ctx, key, http.MethodGet, configURL, nil)
	var config ConfigResponse
	if err := json.Unmarshal(configBody, &config); err != nil {
		t.Fatalf("decode config: %v\n%s", err, configBody)
	}
	if config.Config["backup.last_backup_path"] != secondPath {
		t.Fatalf("last backup path = %#v, want %q", config.Config["backup.last_backup_path"], secondPath)
	}
	if config.Config["backup.last_backup_at"] == "" {
		t.Fatalf("last backup timestamp not set: %#v", config.Config["backup.last_backup_at"])
	}
}

func TestHTTPBackupPassphraseCustodyUsesKeyring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	rpcSrv := newRPCServer(runtimePaths)
	rpcSrv.keyring = newHTTPTestKeyring()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/v1/backups/passphrase", httpSrv.Ports().V4)

	body := signedHTTPJSON(t, ctx, key, http.MethodGet, baseURL, nil)
	var status BackupPassphraseStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode initial status: %v\n%s", err, body)
	}
	if status.Enrolled || status.Available {
		t.Fatalf("initial status = %+v, want not enrolled and unavailable", status)
	}

	body = signedHTTPJSON(t, ctx, key, http.MethodPut, baseURL, []byte(`{"passphrase":"scheduled-passphrase"}`))
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode enroll status: %v\n%s", err, body)
	}
	if !status.Enrolled || !status.Available || status.Source != "keychain" {
		t.Fatalf("enroll status = %+v", status)
	}
	if got, err := rpcSrv.keyring.Get(backupPassphraseSvc, backupPassphraseAccount()); err != nil || got != "scheduled-passphrase" {
		t.Fatalf("stored passphrase = %q err=%v", got, err)
	}

	body = signedHTTPJSON(t, ctx, key, http.MethodDelete, baseURL, nil)
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode delete status: %v\n%s", err, body)
	}
	if status.Enrolled || !status.Available {
		t.Fatalf("delete status = %+v", status)
	}
	if _, err := rpcSrv.keyring.Get(backupPassphraseSvc, backupPassphraseAccount()); err == nil {
		t.Fatal("expected deleted backup passphrase")
	}
}

func TestScheduledBackupUsesKeychainCustodyWhenEnvMissing(t *testing.T) {
	ctx := context.Background()
	t.Setenv("HASP_BACKUP_PASSPHRASE", "")
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	}
	keyring := newHTTPTestKeyring()
	vaultStore, err := store.NewForPaths(keyring, runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(ctx, "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	backupDir := filepath.Join(home, "backups")
	if _, err := handle.SetConfigValue("backup.schedule", "daily", "test"); err != nil {
		t.Fatalf("set schedule: %v", err)
	}
	if _, err := handle.SetConfigValue("backup.destination_path", backupDir, "test"); err != nil {
		t.Fatalf("set destination: %v", err)
	}
	if err := keyring.Set(ctx, backupPassphraseSvc, backupPassphraseAccount(), "scheduled-passphrase"); err != nil {
		t.Fatalf("set backup passphrase custody: %v", err)
	}
	rpcSrv := newRPCServer(runtimePaths)
	rpcSrv.keyring = keyring
	now := time.Date(2026, 5, 11, 2, 0, 0, 0, time.UTC)

	if err := rpcSrv.broker().runScheduledBackupOnce(ctx, now); err != nil {
		t.Fatalf("scheduled backup: %v", err)
	}
	backupPath := filepath.Join(backupDir, "HASP-20260511-020000.hasp-backup")
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("scheduled backup missing: %v", err)
	}
}

func TestBackupScheduleDueAndPath(t *testing.T) {
	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	if backupScheduleDue("off", "", now) {
		t.Fatal("off schedule should not be due")
	}
	if !backupScheduleDue("daily", "", now) {
		t.Fatal("empty last backup should be due")
	}
	if backupScheduleDue("daily", now.Add(-23*time.Hour).Format(time.RFC3339), now) {
		t.Fatal("daily schedule should not be due before 24h")
	}
	if !backupScheduleDue("daily", now.Add(-24*time.Hour).Format(time.RFC3339), now) {
		t.Fatal("daily schedule should be due at 24h")
	}
	if backupScheduleDue("weekly", now.Add(-6*24*time.Hour).Format(time.RFC3339), now) {
		t.Fatal("weekly schedule should not be due before 7d")
	}
	if !backupScheduleDue("weekly", now.Add(-7*24*time.Hour).Format(time.RFC3339), now) {
		t.Fatal("weekly schedule should be due at 7d")
	}
	got := scheduledBackupPath("/tmp/HASP.hasp-backup", now)
	if got != "/tmp/HASP-20260510-080000.hasp-backup" {
		t.Fatalf("scheduled file path = %q", got)
	}
	got = scheduledBackupPath("/tmp/backups", now)
	if got != "/tmp/backups/HASP-20260510-080000.hasp-backup" {
		t.Fatalf("scheduled dir path = %q", got)
	}
}

func runSwiftDaemonClientSmoke(t *testing.T, ctx context.Context, macosPackage string, baseURL string, key []byte, extraArgs ...string) {
	t.Helper()
	args := []string{
		"run",
		"--package-path",
		macosPackage,
		"daemonclient-smoke",
		"--base-url",
		baseURL,
		"--key-hex",
		hex.EncodeToString(key),
	}
	args = append(args, extraArgs...)
	cmd := exec.CommandContext(ctx, "swift", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("swift daemon client smoke failed: %v\n%s", err, string(output))
	}
}

func signedHTTPJSON(t *testing.T, ctx context.Context, key []byte, method string, url string, body []byte) []byte {
	t.Helper()
	out, status := signedHTTPJSONStatus(t, ctx, key, method, url, body)
	if status < 200 || status >= 300 {
		t.Fatalf("%s %s status = %d body=%s", method, url, status, out)
	}
	return out
}

func signedHTTPJSONStatus(t *testing.T, ctx context.Context, key []byte, method string, url string, body []byte) ([]byte, int) {
	t.Helper()
	return signedHTTPJSONStatusWithHeaders(t, ctx, key, method, url, body, nil)
}

func signedHTTPJSONWithHeaders(t *testing.T, ctx context.Context, key []byte, method string, url string, body []byte, headers map[string]string) []byte {
	t.Helper()
	out, status := signedHTTPJSONStatusWithHeaders(t, ctx, key, method, url, body, headers)
	if status < 200 || status >= 300 {
		t.Fatalf("%s %s status = %d body=%s", method, url, status, out)
	}
	return out
}

func signedHTTPJSONStatusWithHeaders(t *testing.T, ctx context.Context, key []byte, method string, url string, body []byte, headers map[string]string) ([]byte, int) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	signRequestWithNonce(req, key, body, time.Now().UTC(), fmt.Sprintf("%032x", time.Now().UnixNano()))
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return out, resp.StatusCode
}

func normalizeJSONMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode JSON map: %v\n%s", err, body)
	}
	return payload
}

func runSwiftDaemonClientSmokeWithEventTrigger(
	t *testing.T,
	ctx context.Context,
	macosPackage string,
	baseURL string,
	key []byte,
	rpcSrv *rpcServer,
	topic string,
) {
	t.Helper()
	args := []string{
		"run",
		"--package-path",
		macosPackage,
		"daemonclient-smoke",
		"--base-url",
		baseURL,
		"--key-hex",
		hex.EncodeToString(key),
		"--events-topic",
		topic,
	}
	cmd := exec.CommandContext(ctx, "swift", args...)
	output := new(bytes.Buffer)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swift daemon client SSE smoke: %v", err)
	}
	broker := &brokerRPC{
		paths:      rpcSrv.paths,
		startedAt:  rpcSrv.startedAt,
		sessions:   rpcSrv.sessions,
		audit:      rpcSrv.audit,
		auditState: rpcSrv.auditState,
		events:     rpcSrv.events,
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("swift daemon client SSE smoke failed: %v\n%s", err, output.String())
			}
			return
		case <-ticker.C:
			var reply LockVaultResponse
			if err := broker.LockVault(LockVaultRequest{Cause: "manual"}, &reply); err != nil {
				t.Fatalf("lock vault for swift daemon client smoke: %v", err)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for swift daemon client SSE smoke\n%s", output.String())
		case <-ctx.Done():
			t.Fatalf("context ended waiting for swift daemon client SSE smoke: %v\n%s", ctx.Err(), output.String())
		}
	}
}

func readSSELines(body io.Reader, lines chan<- string) {
	defer close(lines)
	buf := make([]byte, 1)
	current := make([]byte, 0, 128)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				line := strings.TrimSuffix(string(current), "\r")
				lines <- line
				current = current[:0]
			} else {
				current = append(current, buf[0])
			}
		}
		if err != nil {
			return
		}
	}
}

func waitForSSELine(t *testing.T, lines <-chan string, want string) {
	t.Helper()
	waitForSSELineWithin(t, lines, want, 2*time.Second)
}

func waitForSSELineWithin(t *testing.T, lines <-chan string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("events stream closed before line %q", want)
			}
			if line == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out after %s waiting for SSE line %q", timeout, want)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestHTTPRevealRouteFailsClosedWhenOnlyRequestControlledPIDHintsExist(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          t.TempDir(),
		SocketPath:       "/tmp/hasp.sock",
		HTTPPortFilePath: fmt.Sprintf("%s/daemon.http.port", t.TempDir()),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/v1/items/secret_01/reveal/inline?pid=999999", httpSrv.Ports().V4),
		bytes.NewBufferString(`{"pid":999999,"peer_pid":999999}`),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HASP-Peer-PID", "999999")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.RemoteAddr = "127.0.0.1:999999"
	signRequest(req, key, []byte(`{"pid":999999,"peer_pid":999999}`), time.Now().UTC())

	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("reveal request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when no kernel-backed peer pid source exists", resp.StatusCode)
	}
}

func TestHTTPRevealAuthFailureAppendsAttestationAuditRow(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	runtimeDir := filepath.Join(home, "runtime")
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          home,
		RuntimeDir:       runtimeDir,
		SocketPath:       filepath.Join(runtimeDir, "hasp.sock"),
		HTTPPortFilePath: filepath.Join(home, "daemon.http.port"),
		AuditPath:        filepath.Join(home, "audit.jsonl"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/v1/items/secret_01/reveal/inline", httpSrv.Ports().V4),
		nil,
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(httpapi.HeaderDate, time.Now().UTC().Format(time.RFC3339Nano))
	req.Header.Set(httpapi.HeaderNonce, "00112233445566778899aabbccddeeff")
	req.Header.Set("Authorization", httpapi.AuthorizationScheme+" sig=invalid")

	resp, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatalf("reveal request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	auditBody, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !bytes.Contains(auditBody, []byte(`"action":"transport.attestation.failed"`)) {
		t.Fatalf("audit log missing attestation failure row: %s", auditBody)
	}
	if !bytes.Contains(auditBody, []byte(`"path":"/v1/items/secret_01/reveal/inline"`)) {
		t.Fatalf("audit log missing reveal path: %s", auditBody)
	}
}

func TestHTTPRevealRouteUsesUnixSocketPeerPIDForAttestation(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	oldHTTPAttestor := httpAttestor
	var attestedPID int
	httpAttestor = func() (httpapi.Attestor, error) {
		return runtimeAttestorFunc(func(pid int) error {
			attestedPID = pid
			return nil
		}), nil
	}
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		httpAttestor = oldHTTPAttestor
	})

	runtimeDir := filepath.Join(home, "runtime")
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:          home,
		RuntimeDir:       runtimeDir,
		SocketPath:       filepath.Join(runtimeDir, "hasp.sock"),
		HTTPPortFilePath: filepath.Join(home, "daemon.http.port"),
		AuditPath:        filepath.Join(home, "audit.jsonl"),
	})
	rpcSrv.peerPID = func(conn net.Conn) (uint32, error) {
		if _, ok := conn.(*net.UnixConn); !ok {
			t.Fatalf("peer PID source received %T, want unix connection", conn)
		}
		return 4242, nil
	}
	now := time.Now().UTC()
	rpcSrv.revealItem = func(context.Context, paths.Paths, string) (revealcore.Payload, error) {
		return revealcore.FromItem(store.Item{
			ID:        "item-123",
			Name:      "secret_01",
			Kind:      store.ItemKindKV,
			Value:     []byte("super-secret"),
			CreatedAt: now,
			UpdatedAt: now,
		}), nil
	}
	if _, err := rpcSrv.sessions.OpenInternal("gui", home, time.Minute, false, "hasp-macos"); err != nil {
		t.Fatalf("open internal session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()

	body := []byte(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://hasp/v1/items/secret_01/reveal/inline", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(headerRequestID, "018f6a6b-7c8d-7abc-8def-0123456789ab")
	signRequest(req, key, body, time.Now().UTC())
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "unix", httpSrv.Ports().UnixSocket)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("reveal request over unix socket: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reveal response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", resp.StatusCode, out)
	}
	if attestedPID != 4242 {
		t.Fatalf("attested pid = %d, want unix peer PID 4242", attestedPID)
	}
	payload := normalizeJSONMap(t, out)
	if payload["id"] != "item-123" || payload["name"] != "secret_01" {
		t.Fatalf("unexpected reveal payload: %s", out)
	}
	if payload["value"] == base64.StdEncoding.EncodeToString([]byte("super-secret")) || bytes.Contains(out, []byte("super-secret")) {
		t.Fatalf("reveal response leaked plaintext or raw base64 plaintext: %s", out)
	}
}

func TestHTTPRevealRequestIDIdempotencyAuditsOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	oldHTTPAttestor := httpAttestor
	httpAttestor = func() (httpapi.Attestor, error) {
		return runtimeAttestorFunc(func(pid int) error { return nil }), nil
	}
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		httpAttestor = oldHTTPAttestor
	})

	runtimeDir := filepath.Join(home, "runtime")
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		RuntimeDir:         runtimeDir,
		SocketPath:         filepath.Join(runtimeDir, "hasp.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(runtimeDir, "daemon.http.sock"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
	})
	rpcSrv.peerPID = func(net.Conn) (uint32, error) { return 4242, nil }
	now := time.Now().UTC()
	revealCalls := 0
	var revealCallsMu sync.Mutex
	rpcSrv.revealItem = func(context.Context, paths.Paths, string) (revealcore.Payload, error) {
		revealCallsMu.Lock()
		revealCalls++
		revealCallsMu.Unlock()
		time.Sleep(50 * time.Millisecond)
		return revealcore.FromItem(store.Item{
			ID:        "item-123",
			Name:      "secret_01",
			Kind:      store.ItemKindKV,
			Value:     []byte("super-secret"),
			CreatedAt: now,
			UpdatedAt: now,
		}), nil
	}
	if _, err := rpcSrv.sessions.OpenInternal("gui", home, time.Minute, false, "hasp-macos"); err != nil {
		t.Fatalf("open internal session: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "unix", httpSrv.Ports().UnixSocket)
			},
		},
	}
	requestID := "018f6a6b-7c8d-7abc-8def-0123456789ab"
	body := []byte(`{}`)
	doRevealStatus := func(path string, requestID string, nonce string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://hasp"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set(headerRequestID, requestID)
		signRequestWithNonce(req, key, body, time.Now().UTC(), nonce)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("reveal request: %v", err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp.StatusCode, out
	}
	doReveal := func(nonce string) []byte {
		t.Helper()
		status, out := doRevealStatus("/v1/secrets/secret_01/reveal", requestID, nonce)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 body=%s", status, out)
		}
		return out
	}

	first := doReveal("00112233445566778899aabbccddeeff")
	second := doReveal("11112233445566778899aabbccddeeff")
	if !bytes.Equal(first, second) {
		t.Fatalf("idempotent reveal response changed\nfirst=%s\nsecond=%s", first, second)
	}
	status, out := doRevealStatus("/v1/secrets/other_secret/reveal", requestID, "21112233445566778899aabbccddeeff")
	if status != http.StatusConflict {
		t.Fatalf("mismatched request id reuse status = %d, want 409 body=%s", status, out)
	}
	concurrentRequestID := "018f6a6b-7c8d-7abc-8def-0123456789ac"
	var concurrentFirst, concurrentSecond []byte
	var concurrentFirstStatus, concurrentSecondStatus int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		concurrentFirstStatus, concurrentFirst = doRevealStatus("/v1/secrets/secret_01/reveal", concurrentRequestID, "31112233445566778899aabbccddeeff")
	}()
	go func() {
		defer wg.Done()
		concurrentSecondStatus, concurrentSecond = doRevealStatus("/v1/secrets/secret_01/reveal", concurrentRequestID, "41112233445566778899aabbccddeeff")
	}()
	wg.Wait()
	if concurrentFirstStatus != http.StatusOK {
		t.Fatalf("concurrent first status = %d body=%s", concurrentFirstStatus, concurrentFirst)
	}
	if concurrentSecondStatus != http.StatusOK {
		t.Fatalf("concurrent second status = %d body=%s", concurrentSecondStatus, concurrentSecond)
	}
	if !bytes.Equal(concurrentFirst, concurrentSecond) {
		t.Fatalf("concurrent idempotent reveal response changed\nfirst=%s\nsecond=%s", concurrentFirst, concurrentSecond)
	}
	revealCallsMu.Lock()
	gotRevealCalls := revealCalls
	revealCallsMu.Unlock()
	if gotRevealCalls != 2 {
		t.Fatalf("revealItem calls = %d, want 2 (one initial, one concurrent singleflight)", gotRevealCalls)
	}
	auditBody, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if count := bytes.Count(auditBody, []byte(`"action":"secret.reveal"`)); count != 2 {
		t.Fatalf("secret reveal audit count = %d, want 2\naudit=%s", count, auditBody)
	}
	if !bytes.Contains(auditBody, []byte(`"request_id":"`+requestID+`"`)) {
		t.Fatalf("audit missing request id: %s", auditBody)
	}
}

func TestHTTPRevealLockedVaultAndRateLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	oldHTTPAttestor := httpAttestor
	httpAttestor = func() (httpapi.Attestor, error) {
		return runtimeAttestorFunc(func(pid int) error { return nil }), nil
	}
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		httpAttestor = oldHTTPAttestor
	})

	runtimeDir := filepath.Join(home, "runtime")
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		RuntimeDir:         runtimeDir,
		SocketPath:         filepath.Join(runtimeDir, "hasp.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(runtimeDir, "daemon.http.sock"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
	})
	rpcSrv.peerPID = func(net.Conn) (uint32, error) { return 4242, nil }
	now := time.Now().UTC()
	rpcSrv.revealItem = func(context.Context, paths.Paths, string) (revealcore.Payload, error) {
		return revealcore.FromItem(store.Item{
			ID:        "item-123",
			Name:      "secret_01",
			Kind:      store.ItemKindKV,
			Value:     []byte("super-secret"),
			CreatedAt: now,
			UpdatedAt: now,
		}), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	httpSrv, err := startHTTPServer(ctx, rpcSrv.paths, rpcSrv, errCh)
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() {
		cancel()
		_ = httpSrv.Close()
	}()
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "unix", httpSrv.Ports().UnixSocket)
			},
		},
	}
	body := []byte(`{}`)
	doRevealStatus := func(requestID string, nonce string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://hasp/v1/secrets/secret_01/reveal", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set(headerRequestID, requestID)
		signRequestWithNonce(req, key, body, time.Now().UTC(), nonce)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("reveal request: %v", err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp.StatusCode, out
	}

	status, out := doRevealStatus("018f6a6b-7c8d-7abc-8def-0123456789ab", "00112233445566778899aabbccddeeff")
	if status != http.StatusLocked {
		t.Fatalf("locked reveal status = %d, want 423 body=%s", status, out)
	}
	if _, err := rpcSrv.sessions.OpenInternal("gui", home, time.Minute, false, "hasp-macos"); err != nil {
		t.Fatalf("open internal session: %v", err)
	}
	for i := 0; i < revealRateLimitCount; i++ {
		requestID := fmt.Sprintf("018f6a6b-7c8d-7abc-8def-0123456789%02x", i)
		nonce := fmt.Sprintf("11112233445566778899aabbccddee%02x", i)
		status, out := doRevealStatus(requestID, nonce)
		if status != http.StatusOK {
			t.Fatalf("reveal %d status = %d, want 200 body=%s", i, status, out)
		}
	}
	status, out = doRevealStatus("018f6a6b-7c8d-7abc-8def-0123456789ff", "22112233445566778899aabbccddeeff")
	if status != http.StatusTooManyRequests {
		t.Fatalf("rate-limited reveal status = %d, want 429 body=%s", status, out)
	}
}

func signDashboardRequest(req *http.Request, key []byte, now time.Time) {
	signRequest(req, key, nil, now)
}

type httpTestKeyring struct {
	mu     sync.Mutex
	values map[string]string
}

func newHTTPTestKeyring() *httpTestKeyring {
	return &httpTestKeyring{values: make(map[string]string)}
}

func (k *httpTestKeyring) Set(_ context.Context, service string, account string, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values[service+"\x00"+account] = value
	return nil
}

func (k *httpTestKeyring) Get(service string, account string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.values[service+"\x00"+account]
	if !ok {
		return "", store.ErrKeyringUnavailable
	}
	return value, nil
}

func (k *httpTestKeyring) Delete(service string, account string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.values, service+"\x00"+account)
	return nil
}

func signRequest(req *http.Request, key []byte, body []byte, now time.Time) {
	signRequestWithNonce(req, key, body, now, "00112233445566778899aabbccddeeff")
}

func signRequestWithNonce(req *http.Request, key []byte, body []byte, now time.Time, nonce string) {
	dateValue := now.UTC().Format(time.RFC3339Nano)
	bodySum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(dateValue + "\n" + nonce + "\n" + req.Method + "\n" + req.URL.RequestURI() + "\n" + hex.EncodeToString(bodySum[:])))
	req.Header.Set(httpapi.HeaderDate, dateValue)
	req.Header.Set(httpapi.HeaderNonce, nonce)
	req.Header.Set("Authorization", httpapi.AuthorizationScheme+" sig="+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

type runtimeAttestorFunc func(pid int) error

func (f runtimeAttestorFunc) VerifyPID(pid int) error {
	return f(pid)
}
