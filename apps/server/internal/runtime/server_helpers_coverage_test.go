package runtime

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/accessmatrix"
	"github.com/gethasp/hasp/apps/server/internal/app/auditops"
	revealcore "github.com/gethasp/hasp/apps/server/internal/app/reveal"
	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/integrations"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestServerHTTPParserHelperCoverage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/leases?consumer_id=agent&limit=2&expiring_in=5m", nil)
	leasesReq, err := listLeasesRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("list leases request: %v", err)
	}
	if leasesReq.ConsumerID != "agent" || leasesReq.Limit != 2 || leasesReq.ExpiringInSeconds != 300 {
		t.Fatalf("leases request = %+v", leasesReq)
	}
	for _, raw := range []string{"/v1/leases?limit=bad", "/v1/leases?limit=-1", "/v1/leases?expiring_in=bad"} {
		if _, err := listLeasesRequestFromHTTP(httptest.NewRequest(http.MethodGet, raw, nil)); err == nil {
			t.Fatalf("expected list leases parse error for %s", raw)
		}
	}

	matrixReq, err := accessMatrixRequestFromHTTP(httptest.NewRequest(http.MethodGet, "/v1/access/matrix?limit=3&has_active_lease=true", nil))
	if err != nil {
		t.Fatalf("matrix request: %v", err)
	}
	if matrixReq.Limit != 3 || matrixReq.HasActiveLease == nil || !*matrixReq.HasActiveLease {
		t.Fatalf("matrix request = %+v", matrixReq)
	}
	for _, raw := range []string{"/v1/access/matrix?limit=bad", "/v1/access/matrix?has_active_lease=maybe"} {
		if _, err := accessMatrixRequestFromHTTP(httptest.NewRequest(http.MethodGet, raw, nil)); err == nil {
			t.Fatalf("expected access matrix parse error for %s", raw)
		}
	}

	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/v1/leases/abc/revoke", true},
		{"/v1/leases//revoke", false},
		{"/wrong", false},
	} {
		if _, ok := leaseRevokeIDFromPath(tc.path); ok != tc.ok {
			t.Fatalf("lease path %q ok=%t", tc.path, ok)
		}
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/v1/approvals/abc/decide", true},
		{"/v1/approvals//decide", false},
		{"/wrong", false},
	} {
		if _, ok := approvalDecideIDFromPath(tc.path); ok != tc.ok {
			t.Fatalf("approval decide path %q ok=%t", tc.path, ok)
		}
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/v1/approvals/abc", true},
		{"/v1/approvals/a/b", false},
		{"/v1/approvals/", false},
		{"/wrong", false},
	} {
		if _, ok := approvalDetailIDFromPath(tc.path); ok != tc.ok {
			t.Fatalf("approval detail path %q ok=%t", tc.path, ok)
		}
	}
}

func TestServerIntegrationPathAndJSONHelperCoverage(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/v1/integrations/mcp/profiles", true},
		{"/v1/integrations/mcp/doctor", true},
		{"/v1/integrations/mcp/unknown", false},
		{"/v1/integrations/%2F/profiles", false},
		{"/v1/integrations/mcp/%zz", false},
		{"/wrong", false},
	} {
		if _, _, ok := integrationActionFromPath(tc.path); ok != tc.ok {
			t.Fatalf("integration action path %q ok=%t", tc.path, ok)
		}
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"/v1/integrations/mcp/profiles/codex", true},
		{"/v1/integrations/%2F/profiles/codex", false},
		{"/v1/integrations/mcp/profiles/%2F", false},
		{"/v1/integrations/mcp/profiles/%zz", false},
		{"/v1/integrations/mcp/other/codex", false},
		{"/wrong", false},
	} {
		if _, _, ok := integrationProfilePath(tc.path); ok != tc.ok {
			t.Fatalf("integration profile path %q ok=%t", tc.path, ok)
		}
	}

	var decoded map[string]string
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ok":"yes"}`))
	if !decodeJSONObject(rec, req, &decoded, "trailing") || decoded["ok"] != "yes" {
		t.Fatalf("decode success decoded=%v code=%d", decoded, rec.Code)
	}
	for _, body := range []string{`{`, `{"ok":"yes"} {"extra":"no"}`} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if decodeJSONObject(rec, req, &decoded, "trailing") || rec.Code != http.StatusBadRequest {
			t.Fatalf("decode body %q unexpectedly succeeded code=%d", body, rec.Code)
		}
	}

	for _, tc := range []struct {
		err  error
		code int
	}{
		{integrations.ErrTargetNotFound, http.StatusNotFound},
		{integrations.ErrProfileConflict, http.StatusConflict},
		{integrations.ErrProfileImmutable, http.StatusConflict},
		{integrations.ErrProfileVersion, http.StatusPreconditionFailed},
		{integrations.ErrPreconditionRequired, http.StatusPreconditionRequired},
		{integrations.ErrProfileInvalid, http.StatusUnprocessableEntity},
		{errors.New("boom"), http.StatusInternalServerError},
	} {
		rec = httptest.NewRecorder()
		if !writeIntegrationProfileMutationError(rec, tc.err) || rec.Code != tc.code {
			t.Fatalf("mutation error %v code=%d want %d", tc.err, rec.Code, tc.code)
		}
	}
	rec = httptest.NewRecorder()
	if writeIntegrationProfileMutationError(rec, nil) {
		t.Fatal("nil mutation error should not write")
	}
}

func TestServerAuditAndRevealHelperCoverage(t *testing.T) {
	if got, err := auditLimitFromHTTP(nil); err != nil || got != 10 {
		t.Fatalf("nil audit limit = %d err=%v", got, err)
	}
	if got, err := auditLimitFromHTTP(httptest.NewRequest(http.MethodGet, "/?limit=200000", nil)); err != nil || got != 100000 {
		t.Fatalf("clamped audit limit = %d err=%v", got, err)
	}
	if _, err := auditLimitFromHTTP(httptest.NewRequest(http.MethodGet, "/?limit=bad", nil)); err == nil {
		t.Fatal("expected bad audit limit")
	}
	if opts, err := auditExportOptionsFromHTTP(nil); err != nil || opts != (auditops.ExportOptions{}) {
		t.Fatalf("nil audit export opts = %+v err=%v", opts, err)
	}
	for _, raw := range []string{
		"/?format=json",
		"/?from=bad",
		"/?to=bad",
		"/?from=2026-05-14T12:00:01Z&to=2026-05-14T12:00:00Z",
	} {
		if _, err := auditExportOptionsFromHTTP(httptest.NewRequest(http.MethodGet, raw, nil)); err == nil {
			t.Fatalf("expected audit export parse error for %s", raw)
		}
	}
	if opts, err := auditExportOptionsFromHTTP(httptest.NewRequest(http.MethodGet, "/?format=ndjson&from=2026-05-14T12:00:00Z&to=2026-05-14T12:00:00Z", nil)); err != nil || opts.From.IsZero() || opts.To.IsZero() {
		t.Fatalf("audit export opts = %+v err=%v", opts, err)
	}

	if _, err := revealSecretRef(httptest.NewRequest(http.MethodGet, "/nope", nil)); err == nil {
		t.Fatal("expected non-reveal route error")
	}
	if ref, err := revealSecretRef(httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)); err != nil || ref != "api" {
		t.Fatalf("reveal ref = %q err=%v", ref, err)
	}
	if got := revealActor(httptest.NewRequest(http.MethodPost, "/", nil)); got != "pid:unknown" {
		t.Fatalf("unknown actor = %q", got)
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(httpapiWithPeerPID(req.Context(), 42))
	if got := revealActor(req); got != "pid:42" {
		t.Fatalf("peer actor = %q", got)
	}
	for _, value := range []string{"", "018f6ab2_8e3b-7a1c-b321-123456789abc", "018f6ab2-8e3b-7a1c-b321-123456789abc", "018f6ab2-8e3b-6a1c-b321-123456789abc", "018f6ab28e3b7a1cb321123456789abc", "018f6ab2-8e3b-7a1c-b321-123456789abz"} {
		_ = isUUIDV7(value)
	}
	if !isUUIDV7("018f6ab2-8e3b-7a1c-b321-123456789abc") {
		t.Fatal("expected valid UUIDv7")
	}
}

func TestServerSmallSnapshotHelperCoverage(t *testing.T) {
	if folder, name := splitSecretPath(""); folder != "Vault" || name != "" {
		t.Fatalf("empty split = %q %q", folder, name)
	}
	if folder, name := splitSecretPath("api"); folder != "Vault" || name != "api" {
		t.Fatalf("flat split = %q %q", folder, name)
	}
	if folder, name := splitSecretPath("prod/"); folder != "prod" || name != "prod/" {
		t.Fatalf("folder split = %q %q", folder, name)
	}
	server := &rpcServer{auditState: newAuditState(nil)}
	last, err := server.secretLastRevealed()
	if err != nil || len(last) != 0 {
		t.Fatalf("nil audit last revealed = %v err=%v", last, err)
	}
	badAuditDir := t.TempDir()
	server.audit = audit.NewForPaths(paths.Paths{AuditPath: badAuditDir})
	if _, err := server.auditListSnapshot(10); err == nil {
		t.Fatal("audit list should propagate event read errors")
	}
	if _, err := server.auditVerifySnapshot(true); err == nil {
		t.Fatal("audit verify should propagate event read errors")
	}
	if err := server.auditExportNDJSON(&bytes.Buffer{}, auditops.ExportOptions{}); err == nil {
		t.Fatal("audit export should propagate event read errors")
	}
	if _, err := server.secretLastRevealed(); err == nil {
		t.Fatal("secret last revealed should propagate audit read errors")
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	server.audit = audit.NewForPaths(paths.Paths{AuditPath: auditPath})
	if _, err := server.audit.Append(audit.EventRead, "actor", map[string]any{"action": "secret.reveal"}); err != nil {
		t.Fatalf("append audit without item id: %v", err)
	}
	last, err = server.secretLastRevealed()
	if err != nil || len(last) != 0 {
		t.Fatalf("last revealed without item id = %v err=%v", last, err)
	}
	server.audit.WithKey([]byte("0123456789abcdef0123456789abcdef"))
	server.setHTTPHMACKey(nil)
	if err := server.auditExportNDJSON(&bytes.Buffer{}, auditops.ExportOptions{}); err != nil {
		t.Fatalf("audit export with fallback key: %v", err)
	}
	if pending, oldest := approvalStats(nil); pending != 0 || oldest != 0 {
		t.Fatalf("nil approval stats = %d %d", pending, oldest)
	}
	if got := closedRevealDone(); got == nil {
		t.Fatal("closed reveal done channel is nil")
	}
	if _, err := server.approvalDetailSnapshot("missing"); err == nil {
		t.Fatal("nil approval detail should fail")
	}
	approvalStore := NewApprovalStore()
	approval, err := approvalStore.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", TTL: time.Minute})
	if err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	if _, err := server.audit.Append(audit.EventDeny, "daemon", map[string]any{"action": "approval.decide", "approval_id": approval.ID}); err != nil {
		t.Fatalf("append approval audit: %v", err)
	}
	server.approvals = approvalStore
	detail, err := server.approvalDetailSnapshot(approval.ID)
	if err != nil || len(detail.AuditTrail) == 0 {
		t.Fatalf("approval detail trail=%+v err=%v", detail.AuditTrail, err)
	}
	statusStore := NewSessionStore()
	statusStore.locked = false
	statusServer := &rpcServer{sessions: statusStore}
	if status := statusServer.vaultStatusSnapshot(); status.State != "locked" || !status.Locked {
		t.Fatalf("empty unlocked store status = %+v", status)
	}
}

func TestHTTPServerRouteErrorBranches(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	home := t.TempDir()
	rpcSrv := newRPCServer(paths.Paths{
		HomeDir:            home,
		StatePath:          filepath.Join(home, "vault.json"),
		AuditPath:          filepath.Join(home, "audit.jsonl"),
		RuntimeDir:         filepath.Join(home, "runtime"),
		SocketPath:         filepath.Join(home, "runtime", "hasp.sock"),
		HTTPUnixSocketPath: filepath.Join(home, "http.sock"),
		HTTPPortFilePath:   filepath.Join(home, "daemon.http.port"),
	})
	rpcSrv.keyring = newHTTPTestKeyring()
	rpcSrv.audit = nil
	rpcSrv.auditState = newAuditState(nil)
	rpcSrv.accessMatrixInput = func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error) {
		return accessmatrix.Input{}, store.ErrVaultNotInitialized
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
	base := fmt.Sprintf("http://127.0.0.1:%d", httpSrv.Ports().V4)

	rpcSrv.sessions = nil
	for _, path := range []string{"/v1/dashboard", "/v1/dashboard/vault"} {
		body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, base+path, nil)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("nil sessions dashboard %s status=%d body=%s", path, status, body)
		}
	}
	rpcSrv.sessions = NewSessionStore()

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
		status int
	}{
		{http.MethodGet, "/v1/health", nil, http.StatusOK},
		{http.MethodHead, "/v1/health", nil, http.StatusOK},
		{http.MethodPost, "/v1/health", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/dashboard", nil, http.StatusOK},
		{http.MethodGet, "/v1/dashboard/vault", nil, http.StatusOK},
		{http.MethodGet, "/v1/dashboard/leases", nil, http.StatusOK},
		{http.MethodGet, "/v1/dashboard/approvals", nil, http.StatusOK},
		{http.MethodGet, "/v1/dashboard/audit", nil, http.StatusOK},
		{http.MethodGet, "/v1/dashboard/integrations", nil, http.StatusOK},
		{http.MethodPost, "/v1/dashboard", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/dashboard/vault", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/dashboard/unknown", nil, http.StatusNotFound},
		{http.MethodGet, "/v1/leases", nil, http.StatusOK},
		{http.MethodPost, "/v1/leases", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/leases?limit=bad", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/leases/not-revoke", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/leases/not-revoke", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/leases/lease-1/revoke", []byte(`{`), http.StatusBadRequest},
		{http.MethodGet, "/v1/leases/bulk-revoke", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/leases/bulk-revoke", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/leases/bulk-revoke?consumer=agent", nil, http.StatusOK},
		{http.MethodGet, "/v1/approvals", nil, http.StatusOK},
		{http.MethodPost, "/v1/approvals", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/approvals/a/b", nil, http.StatusNotFound},
		{http.MethodGet, "/v1/approvals/not-found", nil, http.StatusNotFound},
		{http.MethodPut, "/v1/approvals/not-found", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/approvals/not-found", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/approvals/not-found/decide", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/approvals/not-found/decide?granted_ttl_s=bad", nil, http.StatusBadRequest},
		{http.MethodPost, "/v1/approvals/not-found/decide?hold_duration_ms=bad", nil, http.StatusBadRequest},
		{http.MethodPost, "/v1/access/matrix", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/access/matrix?limit=bad", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/access/matrix", nil, http.StatusLocked},
		{http.MethodGet, "/v1/integrations", nil, http.StatusOK},
		{http.MethodPost, "/v1/integrations", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/integrations/profiles", nil, http.StatusOK},
		{http.MethodPost, "/v1/integrations/profiles", []byte(`{"target_id":"mcp","id":"custom","name":"Custom","target_pattern":"hasp mcp","scope":"agent"}`), http.StatusOK},
		{http.MethodPatch, "/v1/integrations/profiles", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/integrations/profiles", []byte(`{`), http.StatusBadRequest},
		{http.MethodGet, "/v1/integrations/mcp/profiles/custom", nil, http.StatusMethodNotAllowed},
		{http.MethodPut, "/v1/integrations/mcp/profiles/custom", []byte(`{"name":"Custom"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPut, "/v1/integrations/mcp/profiles/custom", []byte(`{"name":"Custom","target_pattern":"hasp mcp","scope":"agent"}`), http.StatusPreconditionRequired},
		{http.MethodDelete, "/v1/integrations/mcp/profiles/custom", nil, http.StatusPreconditionRequired},
		{http.MethodGet, "/v1/integrations/mcp/profiles", nil, http.StatusOK},
		{http.MethodPost, "/v1/integrations/mcp/doctor", []byte(`{}`), http.StatusOK},
		{http.MethodGet, "/v1/integrations/missing/profiles", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/integrations/mcp/doctor", []byte(`{"profile_id":"x"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodGet, "/v1/integrations/mcp/doctor", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/policy", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/policy", nil, http.StatusLocked},
		{http.MethodPut, "/v1/policy", []byte(`{`), http.StatusBadRequest},
		{http.MethodPut, "/v1/policy", []byte(`{"rules":[]} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/config", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/config", nil, http.StatusLocked},
		{http.MethodGet, "/v1/config/vault.idle_relock_s", nil, http.StatusMethodNotAllowed},
		{http.MethodPut, "/v1/config/bad/key", []byte(`{"value":1}`), http.StatusNotFound},
		{http.MethodPut, "/v1/config/vault.idle_relock_s", []byte(`{`), http.StatusBadRequest},
		{http.MethodPut, "/v1/config/vault.idle_relock_s", []byte(`{"value":1} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/secrets", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/secrets", nil, http.StatusLocked},
		{http.MethodPost, "/v1/audit", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/audit?limit=bad", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/audit", nil, http.StatusInternalServerError},
		{http.MethodPut, "/v1/audit/verify", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/audit/verify", nil, http.StatusInternalServerError},
		{http.MethodPost, "/v1/audit/export", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/audit/export?format=json", nil, http.StatusBadRequest},
		{http.MethodGet, "/v1/audit/export", nil, http.StatusInternalServerError},
		{http.MethodGet, "/v1/backup", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/backup", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/backup", []byte(`{"destination_path":"/tmp/test","passphrase":"x"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/backup", []byte(`{"destination_path":"","passphrase":"x"}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/backup", []byte(`{"destination_path":"/tmp/test","passphrase":"x"}`), http.StatusLocked},
		{http.MethodPost, "/v1/backups/passphrase", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/backups/passphrase", nil, http.StatusOK},
		{http.MethodPut, "/v1/backups/passphrase", []byte(`{`), http.StatusBadRequest},
		{http.MethodPut, "/v1/backups/passphrase", []byte(`{"passphrase":"secret"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPut, "/v1/backups/passphrase", []byte(`{"passphrase":""}`), http.StatusBadRequest},
		{http.MethodPut, "/v1/backups/passphrase", []byte(`{"passphrase":"secret"}`), http.StatusOK},
		{http.MethodDelete, "/v1/backups/passphrase", nil, http.StatusOK},
		{http.MethodPost, "/v1/vault/status", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/vault/status", nil, http.StatusOK},
		{http.MethodGet, "/v1/vault/init", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/vault/init", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/init", []byte(`{"master_password":"correct horse battery staple"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/init", []byte(`{"master_password":"short"}`), http.StatusUnprocessableEntity},
		{http.MethodGet, "/v1/vault/unlock", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{"method":"device-owner"}`), http.StatusLocked},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{"method":"master-password"}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{"method":"master-password","master_password":"wrong password"}`), http.StatusLocked},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{"method":"unknown"}`), http.StatusBadRequest},
		{http.MethodGet, "/v1/vault/master-password", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/vault/master-password", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/master-password", []byte(`{"current_password":"old","new_password":"new"} {"extra":true}`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/master-password", []byte(`{"current_password":"old","new_password":"new"}`), http.StatusLocked},
		{http.MethodGet, "/v1/vault/lock", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/vault/lock", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/vault/lock", nil, http.StatusOK},
		{http.MethodPost, "/v1/daemon/http-key/fingerprint", nil, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/daemon/http-key/fingerprint", nil, http.StatusOK},
		{http.MethodGet, "/v1/daemon/restart", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/daemon/restart", []byte(`{`), http.StatusBadRequest},
		{http.MethodPost, "/v1/items/api", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/secrets/api", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/items/api/reveal/inline", nil, http.StatusForbidden},
	} {
		body, status := signedHTTPJSONStatus(t, ctx, key, tc.method, base+tc.path, tc.body)
		if status != tc.status {
			t.Fatalf("%s %s status=%d want %d body=%s", tc.method, tc.path, status, tc.status, body)
		}
	}

	rpcSrv.setHTTPHMACKey(nil)
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, base+"/v1/daemon/http-key/fingerprint", nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("missing http key status=%d body=%s", status, body)
	}
	rpcSrv.setHTTPHMACKey(key)

	rpcSrv.keyring = failingDeleteKeyring{Keyring: newHTTPTestKeyring()}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodDelete, base+"/v1/backups/passphrase", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("delete backup passphrase failure status=%d body=%s", status, body)
	}
	rpcSrv.keyring = newHTTPTestKeyring()

	lockedApproval, err := rpcSrv.approvals.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", TTL: time.Minute})
	if err != nil {
		t.Fatalf("queue locked approval: %v", err)
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/approvals/"+lockedApproval.ID+"/decide", []byte(`{"decision":"grant","hold_duration_ms":1500,"auth_method":"touch-id"}`))
	if status != http.StatusLocked {
		t.Fatalf("locked approval decision status=%d body=%s", status, body)
	}

	oldRestart := restartDaemonProcess
	restartCalled := make(chan struct{}, 1)
	restartDaemonProcess = func() { restartCalled <- struct{}{} }
	defer func() { restartDaemonProcess = oldRestart }()
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/daemon/restart", []byte(`{}`))
	if status != http.StatusOK || !strings.Contains(string(body), `"operator"`) {
		t.Fatalf("restart status=%d body=%s", status, body)
	}
	select {
	case <-restartCalled:
		restartDaemonProcess = oldRestart
	case <-time.After(time.Second):
		t.Fatal("restart process was not called")
	}
}

func TestHTTPServerResidualRouteBranches(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	t.Cleanup(func() { httpHMACKey = oldHTTPHMACKey })

	httpHMACKey = func(context.Context) ([]byte, error) { return nil, errors.New("missing hmac") }
	if _, err := startHTTPServer(context.Background(), paths.Paths{HomeDir: t.TempDir()}, newRPCServer(paths.Paths{HomeDir: t.TempDir()}), make(chan error, 1)); err == nil {
		t.Fatal("expected missing HMAC startup failure")
	}
	httpHMACKey = func(context.Context) ([]byte, error) { return nil, nil }
	if _, err := startHTTPServer(context.Background(), paths.Paths{HomeDir: t.TempDir()}, newRPCServer(paths.Paths{HomeDir: t.TempDir()}), make(chan error, 1)); err == nil {
		t.Fatal("expected invalid HMAC startup failure")
	}
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }

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
	rpcSrv.auditState = newAuditState(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpSrv, err := startHTTPServer(ctx, runtimePaths, rpcSrv, make(chan error, 1))
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() { _ = httpSrv.Close() }()
	base := fmt.Sprintf("http://127.0.0.1:%d", httpSrv.Ports().V4)

	rpcSrv.sessions = nil
	for _, tc := range []struct {
		method string
		path   string
		body   []byte
		status int
	}{
		{http.MethodGet, "/v1/leases", nil, http.StatusInternalServerError},
		{http.MethodPost, "/v1/leases/lease-1/revoke", nil, http.StatusBadRequest},
		{http.MethodPost, "/v1/leases/bulk-revoke", nil, http.StatusBadRequest},
	} {
		body, status := signedHTTPJSONStatus(t, ctx, key, tc.method, base+tc.path, tc.body)
		if status != tc.status {
			t.Fatalf("nil sessions %s %s status=%d want %d body=%s", tc.method, tc.path, status, tc.status, body)
		}
	}

	rpcSrv.sessions = NewSessionStore()
	rpcSrv.approvals = nil
	for _, tc := range []struct {
		method string
		path   string
		body   []byte
		status int
	}{
		{http.MethodGet, "/v1/approvals", nil, http.StatusInternalServerError},
		{http.MethodGet, "/v1/approvals/approval-1", nil, http.StatusNotFound},
		{http.MethodPost, "/v1/approvals/approval-1/decide", []byte(`{"decision":"deny"}`), http.StatusBadRequest},
	} {
		body, status := signedHTTPJSONStatus(t, ctx, key, tc.method, base+tc.path, tc.body)
		if status != tc.status {
			t.Fatalf("nil approvals %s %s status=%d want %d body=%s", tc.method, tc.path, status, tc.status, body)
		}
	}

	rpcSrv.approvals = NewApprovalStore()
	rpcSrv.accessMatrixInput = func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error) {
		return accessmatrix.Input{}, errors.New("matrix failed")
	}
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodGet, base+"/v1/access/matrix", nil)
	if status != http.StatusInternalServerError {
		t.Fatalf("matrix failure status=%d body=%s", status, body)
	}
}

func TestHTTPServerSeamedFailureBranches(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	oldHTTPHMACKey := httpHMACKey
	oldHTTPAttestor := httpAttestor
	oldServeHTTPServer := serveHTTPServer
	oldNewStoreForPaths := newStoreForPaths
	oldStoreInitVault := storeInitVault
	oldStoreOpenWithPassword := storeOpenWithPassword
	oldStoreOpenWithConvenienceUnlock := storeOpenWithConvenienceUnlock
	oldEnableConvenienceUnlock := handleEnableConvenienceUnlock
	oldHandleRekeyPassword := handleRekeyPassword
	oldBrokerOpenSession := brokerOpenSession
	oldBrokerLockVault := brokerLockVault
	t.Cleanup(func() {
		httpHMACKey = oldHTTPHMACKey
		httpAttestor = oldHTTPAttestor
		serveHTTPServer = oldServeHTTPServer
		newStoreForPaths = oldNewStoreForPaths
		storeInitVault = oldStoreInitVault
		storeOpenWithPassword = oldStoreOpenWithPassword
		storeOpenWithConvenienceUnlock = oldStoreOpenWithConvenienceUnlock
		handleEnableConvenienceUnlock = oldEnableConvenienceUnlock
		handleRekeyPassword = oldHandleRekeyPassword
		brokerOpenSession = oldBrokerOpenSession
		brokerLockVault = oldBrokerLockVault
	})
	httpHMACKey = func(context.Context) ([]byte, error) { return key, nil }

	httpAttestor = func() (httpapi.Attestor, error) { return nil, errors.New("attestor failed") }
	if _, err := startHTTPServer(context.Background(), paths.Paths{HomeDir: t.TempDir()}, newRPCServer(paths.Paths{HomeDir: t.TempDir()}), make(chan error, 1)); err == nil {
		t.Fatal("expected attestor failure")
	}
	httpAttestor = oldHTTPAttestor

	serveErr := errors.New("serve failed")
	serveHTTPServer = func(*httpapi.Server, context.Context) error { return serveErr }
	errCh := make(chan error, 1)
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
	httpSrv, err := startHTTPServer(context.Background(), runtimePaths, newRPCServer(runtimePaths), errCh)
	if err != nil {
		t.Fatalf("start seamed serve server: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "serve failed") {
			t.Fatalf("serve err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected serve error")
	}
	_ = httpSrv.Close()
	serveHTTPServer = oldServeHTTPServer

	rpcSrv := newRPCServer(runtimePaths)
	rpcSrv.keyring = newHTTPTestKeyring()
	rpcSrv.auditState = newAuditState(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpSrv, err = startHTTPServer(ctx, runtimePaths, rpcSrv, make(chan error, 1))
	if err != nil {
		t.Fatalf("start http server: %v", err)
	}
	defer func() { _ = httpSrv.Close() }()
	base := fmt.Sprintf("http://127.0.0.1:%d", httpSrv.Ports().V4)

	newStoreForPaths = func(store.Keyring, paths.Paths) (*store.Store, error) { return nil, errors.New("new store failed") }
	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodGet, "/v1/policy", nil},
		{http.MethodPut, "/v1/policy", []byte(`{"rules":[]}`)},
		{http.MethodGet, "/v1/config", nil},
		{http.MethodPut, "/v1/config/vault.idle_relock_s", []byte(`{"value":120}`)},
		{http.MethodGet, "/v1/secrets", nil},
		{http.MethodGet, "/v1/access/matrix", nil},
		{http.MethodPost, "/v1/vault/init", []byte(`{"master_password":"correct horse battery staple"}`)},
		{http.MethodPost, "/v1/vault/unlock", []byte(`{"method":"master-password","master_password":"correct horse battery staple"}`)},
		{http.MethodPost, "/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`)},
	} {
		body, status := signedHTTPJSONStatus(t, ctx, key, tc.method, base+tc.path, tc.body)
		if status != http.StatusInternalServerError {
			t.Fatalf("new store %s status=%d body=%s", tc.path, status, body)
		}
	}
	newStoreForPaths = oldNewStoreForPaths

	badCatalogHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(badCatalogHome, "integrations.profiles.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad catalog: %v", err)
	}
	rpcSrv.paths.HomeDir = badCatalogHome
	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodGet, "/v1/integrations", nil},
		{http.MethodGet, "/v1/integrations/profiles", nil},
		{http.MethodPost, "/v1/integrations/profiles", []byte(`{"target_id":"mcp","id":"broken","name":"Broken","target_pattern":"hasp mcp","scope":"agent"}`)},
		{http.MethodGet, "/v1/integrations/mcp/profiles", nil},
		{http.MethodPost, "/v1/integrations/mcp/doctor", []byte(`{}`)},
	} {
		body, status := signedHTTPJSONStatus(t, ctx, key, tc.method, base+tc.path, tc.body)
		if status != http.StatusInternalServerError {
			t.Fatalf("bad catalog %s %s status=%d body=%s", tc.method, tc.path, status, body)
		}
	}

	storeInitVault = func(*store.Store, context.Context, string) error { return errors.New("init failed") }
	body, status := signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/init", []byte(`{"master_password":"correct horse battery staple"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("init failure status=%d body=%s", status, body)
	}
	storeInitVault = oldStoreInitVault

	storeOpenWithPassword = func(*store.Store, context.Context, string) (*store.Handle, error) {
		return nil, errors.New("open failed")
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/init", []byte(`{"master_password":"correct horse battery staple"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("init open failure status=%d body=%s", status, body)
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/unlock", []byte(`{"method":"master-password","master_password":"correct horse battery staple"}`))
	if status != http.StatusLocked {
		t.Fatalf("unlock open failure status=%d body=%s", status, body)
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("master open failure status=%d body=%s", status, body)
	}
	storeOpenWithPassword = func(*store.Store, context.Context, string) (*store.Handle, error) {
		return nil, store.ErrInvalidPassword
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusForbidden {
		t.Fatalf("master invalid password status=%d body=%s", status, body)
	}
	storeOpenWithPassword = func(*store.Store, context.Context, string) (*store.Handle, error) {
		return nil, store.ErrVaultNotInitialized
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusLocked {
		t.Fatalf("master uninitialized status=%d body=%s", status, body)
	}
	storeOpenWithPassword = oldStoreOpenWithPassword

	handleEnableConvenienceUnlock = func(*store.Handle, context.Context) error { return errors.New("convenience failed") }
	freshHome := t.TempDir()
	rpcSrv.paths.HomeDir = freshHome
	rpcSrv.paths.StatePath = filepath.Join(freshHome, "vault.json")
	rpcSrv.paths.AuditPath = filepath.Join(freshHome, "audit.jsonl")
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/init", []byte(`{"master_password":"correct horse battery staple 2"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("convenience failure status=%d body=%s", status, body)
	}
	handleEnableConvenienceUnlock = oldEnableConvenienceUnlock

	brokerOpenSession = func(*brokerRPC, OpenSessionRequest, *OpenSessionResponse) error { return errors.New("session failed") }
	freshHome = t.TempDir()
	rpcSrv.paths.HomeDir = freshHome
	rpcSrv.paths.StatePath = filepath.Join(freshHome, "vault.json")
	rpcSrv.paths.AuditPath = filepath.Join(freshHome, "audit.jsonl")
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/init", []byte(`{"master_password":"correct horse battery staple 3"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("init session failure status=%d body=%s", status, body)
	}
	rpcSrv.validateVaultUnlock = func(context.Context, paths.Paths) error { return nil }
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/unlock", []byte(`{"method":"device-owner"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("unlock session failure status=%d body=%s", status, body)
	}
	rpcSrv.validateVaultUnlock = nil
	brokerOpenSession = oldBrokerOpenSession

	storeOpenWithConvenienceUnlock = func(*store.Store, context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	brokerOpenSession = func(_ *brokerRPC, _ OpenSessionRequest, reply *OpenSessionResponse) error {
		reply.ExpiresAt = time.Now().Add(-time.Second)
		return nil
	}
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/unlock", []byte(`{"method":"device-owner"}`))
	if status != http.StatusOK || !strings.Contains(string(body), `"remaining_ttl":0`) {
		t.Fatalf("device owner unlock with expired reply status=%d body=%s", status, body)
	}
	storeOpenWithConvenienceUnlock = oldStoreOpenWithConvenienceUnlock
	brokerOpenSession = oldBrokerOpenSession

	brokerLockVault = func(*brokerRPC, LockVaultRequest, *LockVaultResponse) error { return errors.New("lock failed") }
	for _, path := range []string{"/v1/vault/lock", "/v1/daemon/restart"} {
		body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+path, []byte(`{}`))
		if status != http.StatusInternalServerError {
			t.Fatalf("lock failure %s status=%d body=%s", path, status, body)
		}
	}
	brokerLockVault = oldBrokerLockVault

	storeOpenWithPassword = func(*store.Store, context.Context, string) (*store.Handle, error) { return &store.Handle{}, nil }
	handleRekeyPassword = func(*store.Handle, context.Context, string, string) error { return store.ErrInvalidPassword }
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusForbidden {
		t.Fatalf("rekey invalid status=%d body=%s", status, body)
	}
	handleRekeyPassword = func(*store.Handle, context.Context, string, string) error { return errors.New("weak new password") }
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("rekey invalid new status=%d body=%s", status, body)
	}
	handleRekeyPassword = func(*store.Handle, context.Context, string, string) error { return nil }
	brokerLockVault = func(*brokerRPC, LockVaultRequest, *LockVaultResponse) error { return errors.New("lock failed") }
	body, status = signedHTTPJSONStatus(t, ctx, key, http.MethodPost, base+"/v1/vault/master-password", []byte(`{"current_password":"old password ok","new_password":"new password ok"}`))
	if status != http.StatusInternalServerError {
		t.Fatalf("rekey lock failure status=%d body=%s", status, body)
	}
	storeOpenWithPassword = oldStoreOpenWithPassword
	handleRekeyPassword = oldHandleRekeyPassword
	brokerLockVault = oldBrokerLockVault
}

func TestHTTPRevealHandlerBranches(t *testing.T) {
	home := t.TempDir()
	server := newRPCServer(paths.Paths{
		HomeDir:   home,
		AuditPath: filepath.Join(home, "audit.jsonl"),
	})
	key := []byte("0123456789abcdef0123456789abcdef")
	server.setHTTPHMACKey(key)
	server.revealItem = func(_ context.Context, _ paths.Paths, ref string) (revealcore.Payload, error) {
		switch ref {
		case "missing":
			return revealcore.Payload{}, store.ErrItemNotFound
		case "locked":
			return revealcore.Payload{}, store.ErrKeyringUnavailable
		case "boom":
			return revealcore.Payload{}, errors.New("boom")
		default:
			return revealcore.Payload{
				ID:        ref,
				Name:      ref,
				Value:     []byte("secret-value"),
				UpdatedAt: time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
			}, nil
		}
	}
	rec := httptest.NewRecorder()
	server.handleHTTPReveal(rec, httptest.NewRequest(http.MethodPost, "/v1/items/api", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non reveal status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	req.Header.Set(headerRequestID, "not-a-uuid")
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad request id status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789abc")
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusLocked {
		t.Fatalf("locked status = %d", rec.Code)
	}

	if _, err := server.sessions.Open("host", "/tmp/project", time.Minute, false, "consumer"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	conflictDone := make(chan struct{})
	server.revealInflight["018f6ab2-8e3b-7a1c-b321-123456789ad0"] = &revealInflight{
		actor:     "pid:unknown",
		secretRef: "other",
		done:      conflictDone,
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/conflict/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ad0")
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("inflight conflict status = %d", rec.Code)
	}
	failedDone := make(chan struct{})
	close(failedDone)
	server.revealInflight["018f6ab2-8e3b-7a1c-b321-123456789ac4"] = &revealInflight{
		actor:     "pid:unknown",
		secretRef: "failed",
		err:       errors.New("inflight failed"),
		done:      failedDone,
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/failed/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ac4")
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed inflight status = %d", rec.Code)
	}
	for _, tc := range []struct {
		ref       string
		requestID string
		status    int
	}{
		{"missing", "018f6ab2-8e3b-7a1c-b321-123456789abd", http.StatusNotFound},
		{"locked", "018f6ab2-8e3b-7a1c-b321-123456789abe", http.StatusLocked},
		{"boom", "018f6ab2-8e3b-7a1c-b321-123456789abf", http.StatusInternalServerError},
	} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/v1/items/"+tc.ref+"/reveal/inline", nil)
		req.Header.Set(headerRequestID, tc.requestID)
		server.handleHTTPReveal(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("%s reveal status = %d want %d body=%s", tc.ref, rec.Code, tc.status, rec.Body.String())
		}
	}
	oldRevealRand := revealRandRead
	revealRandRead = func([]byte) (int, error) { return 0, errors.New("handler entropy failed") }
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/entropy/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ad1")
	server.handleHTTPReveal(rec, req)
	revealRandRead = oldRevealRand
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("handler build reveal failure status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/no-key/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ac0")
	server.setHTTPHMACKey(nil)
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("missing hmac key status = %d", rec.Code)
	}
	server.setHTTPHMACKey(key)

	rec = httptest.NewRecorder()
	oldRevealJSONMarshal := revealJSONMarshal
	revealJSONMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal reveal failed") }
	req = httptest.NewRequest(http.MethodPost, "/v1/items/marshal/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ac5")
	server.handleHTTPReveal(rec, req)
	revealJSONMarshal = oldRevealJSONMarshal
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("marshal reveal status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/audit/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ac1")
	server.audit = nil
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("missing audit status = %d", rec.Code)
	}
	server.audit = audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "reveal-audit.jsonl")})

	requestID := "018f6ab2-8e3b-7a1c-b321-123456789ac2"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	req.Header.Set(headerRequestID, requestID)
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"algorithm"`) {
		t.Fatalf("success reveal status=%d body=%s", rec.Code, rec.Body.String())
	}
	cached := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	req.Header.Set(headerRequestID, requestID)
	server.handleHTTPReveal(cached, req)
	if cached.Code != http.StatusOK || cached.Body.String() != rec.Body.String() {
		t.Fatalf("cached reveal status=%d body=%s want %s", cached.Code, cached.Body.String(), rec.Body.String())
	}
	conflict := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/other/reveal/inline", nil)
	req.Header.Set(headerRequestID, requestID)
	server.handleHTTPReveal(conflict, req)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict reveal status = %d", conflict.Code)
	}

	server.revealRates["pid:unknown"] = nil
	for i := 0; i < revealRateLimitCount; i++ {
		server.revealRates["pid:unknown"] = append(server.revealRates["pid:unknown"], time.Now().UTC())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/items/limited/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ac3")
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited reveal status = %d", rec.Code)
	}
}

func TestBuildRevealResponseFailureBranches(t *testing.T) {
	server := newRPCServer(paths.Paths{HomeDir: t.TempDir()})
	item := revealcore.Payload{ID: "api", Name: "api", Value: []byte("secret"), UpdatedAt: time.Now().UTC()}
	key := []byte("0123456789abcdef0123456789abcdef")
	requestID := "018f6ab2-8e3b-7a1c-b321-123456789abc"

	oldRandRead := revealRandRead
	revealRandRead = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if _, err := server.buildRevealResponse(key, item, requestID); err == nil {
		t.Fatal("expected nonce failure")
	}
	revealRandRead = oldRandRead

	oldNewCipher := revealNewCipher
	revealNewCipher = func([]byte) (cipher.Block, error) { return nil, errors.New("cipher failed") }
	if _, err := server.buildRevealResponse(key, item, requestID); err == nil {
		t.Fatal("expected cipher failure")
	}
	revealNewCipher = oldNewCipher

	oldNewGCM := revealNewGCM
	revealNewGCM = func(cipher.Block) (cipher.AEAD, error) { return nil, errors.New("gcm failed") }
	if _, err := server.buildRevealResponse(key, item, requestID); err == nil {
		t.Fatal("expected gcm failure")
	}
	revealNewGCM = oldNewGCM
}

func TestHTTPRevealHandlerUsesDefaultRevealItem(t *testing.T) {
	oldOpenConvenience := storeOpenWithConvenienceUnlock
	oldRevealFind := revealFind
	t.Cleanup(func() {
		storeOpenWithConvenienceUnlock = oldOpenConvenience
		revealFind = oldRevealFind
	})
	storeOpenWithConvenienceUnlock = func(*store.Store, context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	revealFind = func(*store.Handle, string) (revealcore.Payload, error) {
		return revealcore.Payload{ID: "api", Name: "api", Value: []byte("secret"), UpdatedAt: time.Now().UTC()}, nil
	}
	home := t.TempDir()
	server := newRPCServer(paths.Paths{HomeDir: home, AuditPath: filepath.Join(home, "audit.jsonl")})
	server.revealItem = nil
	server.audit = audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")})
	server.setHTTPHMACKey([]byte("0123456789abcdef0123456789abcdef"))
	if _, err := server.sessions.Open("host", home, time.Minute, false, "agent"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	req.Header.Set(headerRequestID, "018f6ab2-8e3b-7a1c-b321-123456789ae0")
	rec := httptest.NewRecorder()
	server.handleHTTPReveal(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("default reveal status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestServerRemainingPureRuntimeBranches(t *testing.T) {
	if os.Getenv("HASP_TEST_RESTART_DAEMON_PROCESS") == "1" {
		restartDaemonProcess()
		return
	}
	t.Setenv("HASP_DAEMON_STARTUP_TIMEOUT", "250ms")
	if daemonStartupTimeout() != 250*time.Millisecond {
		t.Fatalf("custom daemon timeout = %s", daemonStartupTimeout())
	}
	t.Setenv("HASP_DAEMON_STARTUP_TIMEOUT", "-1s")
	if daemonStartupTimeout() != defaultDaemonStartupTimeout {
		t.Fatalf("invalid daemon timeout should default, got %s", daemonStartupTimeout())
	}
	oldRuntimeRemove := runtimeRemove
	oldSpawnDaemon := spawnDaemonProcess
	removeCalls := 0
	runtimeRemove = func(string) error {
		removeCalls++
		if removeCalls == 1 {
			return os.ErrNotExist
		}
		return errors.New("sidecar remove failed")
	}
	spawnDaemonProcess = func(context.Context) error { return nil }
	manager := &Manager{paths: paths.Paths{
		RuntimeDir:         t.TempDir(),
		SocketPath:         filepath.Join(t.TempDir(), "hasp.sock"),
		HTTPPortFilePath:   filepath.Join(t.TempDir(), "daemon.http.port"),
		HTTPUnixSocketPath: filepath.Join(t.TempDir(), "http.sock"),
	}}
	if err := manager.EnsureDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "sidecar") {
		t.Fatalf("sidecar remove err=%v", err)
	}
	runtimeRemove = oldRuntimeRemove
	spawnDaemonProcess = oldSpawnDaemon

	server := &rpcServer{
		auditState:          newAuditState(nil),
		events:              newRuntimeEventHub(),
		revealCache:         map[string]revealCacheEntry{},
		revealInflight:      map[string]*revealInflight{},
		revealRates:         map[string][]time.Time{},
		masterPasswordRates: map[string][]time.Time{},
	}
	server.setHTTPListener(httpapi.PortFileState{V6: 9443})
	if server.httpListener.Host != "::1" || server.httpListener.Port != 9443 {
		t.Fatalf("v6 listener = %+v", server.httpListener)
	}
	now := time.Now().UTC()
	server.revealCache["expired"] = revealCacheEntry{expiresAt: now.Add(-time.Second), actor: "a", secretRef: "s"}
	server.revealCache["live"] = revealCacheEntry{expiresAt: now.Add(time.Minute), actor: "a", secretRef: "s", status: http.StatusAccepted, body: []byte("cached")}
	entry, ok, err := server.revealCacheGet("live", "a", "s")
	if err != nil || !ok || string(entry.body) != "cached" {
		t.Fatalf("cache get entry=%+v ok=%t err=%v", entry, ok, err)
	}
	entry.body[0] = 'X'
	if string(server.revealCache["live"].body) == "Xached" {
		t.Fatal("cache entry body should be cloned")
	}
	if _, _, err := server.revealCacheGet("live", "other", "s"); err == nil {
		t.Fatal("cache conflict should fail")
	}
	if _, _, err := server.revealBegin("live", "other", "s"); err == nil {
		t.Fatal("cached reveal begin conflict should fail")
	}
	if _, ok := server.revealCache["expired"]; ok {
		t.Fatal("expired reveal cache entry should be pruned")
	}
	inflight, owner, err := server.revealBegin("live", "a", "s")
	if err != nil || owner {
		t.Fatalf("cached reveal begin inflight=%+v owner=%t err=%v", inflight, owner, err)
	}
	server.revealInflight["busy"] = &revealInflight{actor: "a", secretRef: "s", done: make(chan struct{})}
	if _, owner, err := server.revealBegin("busy", "a", "s"); err != nil || owner {
		t.Fatalf("existing inflight owner=%t err=%v", owner, err)
	}
	if _, _, err := server.revealBegin("busy", "a", "other"); err == nil {
		t.Fatal("inflight conflict should fail")
	}
	coldServer := &rpcServer{}
	if _, ok, err := coldServer.revealCacheGet("missing", "actor", "secret"); err != nil || ok {
		t.Fatalf("cold cache get ok=%t err=%v", ok, err)
	}
	if inflight, owner, err := coldServer.revealBegin("new", "actor", "secret"); err != nil || !owner || inflight == nil {
		t.Fatalf("cold reveal begin inflight=%+v owner=%t err=%v", inflight, owner, err)
	}
	coldServer.publishQueuedApproval(approvals.Approval{ID: "approval"})

	rec := &nonFlushingRecorder{}
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	server.handleHTTPEvents(rec, req)
	if !strings.Contains(rec.String(), "connected") {
		t.Fatalf("non-flushing events body = %q", rec.String())
	}
	rec = &nonFlushingRecorder{}
	server.handleHTTPEvents(rec, httptest.NewRequest(http.MethodPost, "/v1/events", nil))
	if rec.code != http.StatusMethodNotAllowed {
		t.Fatalf("events method status = %d", rec.code)
	}
	server.events = newRuntimeEventHub()
	server.events.publish("skip.topic", `{"skip":true}`)
	server.events.publish("keep.topic", `{"keep":true}`)
	cancelledCtx, cancelEvents := context.WithCancel(context.Background())
	cancelEvents()
	flushRec := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/events?topic=keep.topic", nil).WithContext(cancelledCtx)
	req.Header.Set("Last-Event-ID", "0")
	server.handleHTTPEvents(flushRec, req)
	if body := flushRec.Body.String(); !strings.Contains(body, "keep.topic") || strings.Contains(body, "skip.topic") {
		t.Fatalf("filtered replay body = %q", body)
	}
	liveCtx, cancelLive := context.WithCancel(context.Background())
	defer cancelLive()
	doneEvents := make(chan struct{})
	go func() {
		server.handleHTTPEvents(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/events", nil).WithContext(liveCtx))
		close(doneEvents)
	}()
	deadline := time.After(time.Second)
	for {
		server.events.mu.Lock()
		var subscribed chan runtimeEvent
		for ch := range server.events.subscribers {
			subscribed = ch
			break
		}
		if subscribed != nil {
			delete(server.events.subscribers, subscribed)
			close(subscribed)
			server.events.mu.Unlock()
			break
		}
		server.events.mu.Unlock()
		select {
		case <-deadline:
			cancelLive()
			t.Fatal("event subscriber was not registered")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-doneEvents:
	case <-time.After(time.Second):
		cancelLive()
		t.Fatal("events handler did not exit after closed subscription")
	}
	if topics := requestedEventTopics(httptest.NewRequest(http.MethodGet, "/?topic=a,b&topics=c", nil)); strings.Join(topics, ",") != "a,b,c" {
		t.Fatalf("topics = %#v", topics)
	}
	if requestedEventTopicSet(nil) != nil {
		t.Fatal("nil topic set should be nil")
	}
	hub := newRuntimeEventHub()
	hub.maxHistory = 1
	sub := hub.subscribe()
	hub.publish("a", "{}")
	hub.publish("b", "{}")
	if replay := hub.replaySince("0"); len(replay) != 1 || replay[0].Name != "b" {
		t.Fatalf("replay = %+v", replay)
	}
	hub.unsubscribe(sub)
	hub.unsubscribe(sub)
	var nilHub *runtimeEventHub
	nilHub.publish("none", "{}")
	if nilHub.replaySince("1") != nil {
		t.Fatal("nil hub replay should be nil")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	if got := server.masterPasswordCallerKey(req); got != "remote:127.0.0.1" {
		t.Fatalf("caller key = %q", got)
	}
	req.RemoteAddr = "bad remote"
	if got := server.masterPasswordCallerKey(req); got != "remote:bad remote" {
		t.Fatalf("fallback caller key = %q", got)
	}
	if got := server.masterPasswordCallerKey(nil); got != "remote:unknown" {
		t.Fatalf("unknown caller key = %q", got)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/vault/master-password", nil)
	req = req.WithContext(httpapiWithPeerPID(req.Context(), 99))
	if got := server.masterPasswordCallerKey(req); got != "pid:99" {
		t.Fatalf("peer pid caller key = %q", got)
	}
	details := server.httpAuditDetails(nil, "action")
	if len(details) != 1 || details["action"] != "action" {
		t.Fatalf("nil audit details = %+v", details)
	}
	req.RemoteAddr = "127.0.0.1:4567"
	req.Header.Set("User-Agent", "test-agent")
	details = server.httpAuditDetails(req, "action")
	if details["peer_pid"] != 99 || details["remote_addr"] == "" || details["user_agent"] != "test-agent" {
		t.Fatalf("peer audit details = %+v", details)
	}
	key := "caller"
	for i := 0; i < masterPasswordFailureLimit; i++ {
		server.recordMasterPasswordFailure(key, now.Add(time.Duration(i)*time.Second))
	}
	if retry := server.masterPasswordRetryAfter(key, now.Add(3*time.Second)); retry <= 0 {
		t.Fatalf("retry after = %s", retry)
	}
	server.clearMasterPasswordFailures(key)
	if retry := server.masterPasswordRetryAfter(key, now.Add(4*time.Second)); retry != 0 {
		t.Fatalf("retry after after clear = %s", retry)
	}
	emptyRatesServer := &rpcServer{}
	if retry := emptyRatesServer.masterPasswordRetryAfter("new", now); retry != 0 {
		t.Fatalf("empty retry after = %s", retry)
	}
	var nilServer *rpcServer
	nilServer.recordMasterPasswordFailure("x", now)
	nilServer.clearMasterPasswordFailures("x")
	if nilServer.masterPasswordRetryAfter("x", now) != 0 {
		t.Fatal("nil server retry should be zero")
	}
	nilServer.appendDaemonSecurityAudit(audit.EventDeny, map[string]any{"action": "nil"})

	if !backupScheduleDue("daily", "not-time", now) || backupScheduleDue("monthly", now.Add(-time.Hour).Format(time.RFC3339), now) || backupScheduleDue("daily", now.Add(time.Hour).Format(time.RFC3339), now) {
		t.Fatal("backup schedule edge cases failed")
	}
	if got := scheduledBackupPath("/tmp/backups/", now); !strings.Contains(got, "HASP-") {
		t.Fatalf("scheduled path = %q", got)
	}
	if got := configStringSlice([]string{"a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("string slice = %#v", got)
	}
	if got := configStringSlice([]any{" a ", 1, ""}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("any string slice = %#v", got)
	}
	if statusFromIntegrationDoctor(IntegrationDoctorResponse{RuntimeProbe: true, OK: true}) != "ok" ||
		statusFromIntegrationDoctor(IntegrationDoctorResponse{RuntimeProbe: true, OK: false}) != "degraded" ||
		statusFromIntegrationDoctor(IntegrationDoctorResponse{RuntimeProbe: false, OK: true}) != "metadata_only" {
		t.Fatal("doctor status mapping failed")
	}
	if got := uniqueNonEmptyStrings([]string{" a ", "", "a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("unique strings = %#v", got)
	}
	payload := leaseChangedEventPayload([]Session{
		{ID: "internal", Internal: true},
		{ID: "lease-1", ConsumerName: "consumer", LeaseSecretID: "secret", OpenedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now},
	}, "revoked")
	if !strings.Contains(payload, `"lease_id":"lease-1"`) || strings.Contains(payload, "internal") {
		t.Fatalf("lease changed payload = %s", payload)
	}
	revokedAt := now
	view := sessionLeaseView(Session{ID: "lease-2", RevokedAt: &revokedAt})
	if view.Status != "revoked" {
		t.Fatalf("revoked lease view = %+v", view)
	}
	_ = leases.Lease{ID: "keep import used"}
}

func TestRestartDaemonProcessDefaultExitCode(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestServerRemainingPureRuntimeBranches")
	cmd.Env = append(os.Environ(), "HASP_TEST_RESTART_DAEMON_PROCESS=1")
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 75 {
		t.Fatalf("restart daemon exit err = %v", err)
	}
}

func TestRuntimeStoreAndBrokerResidualBranches(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	approvalStore := NewApprovalStore()
	approvalStore.now = func() time.Time { return now }
	var queued approvals.Approval
	approvalStore.SetOnQueue(func(a approvals.Approval) { queued = a })
	if _, err := approvalStore.Queue(QueueApprovalInput{RequesterConsumerID: "agent"}); err == nil {
		t.Fatal("queue without secret should fail")
	}
	if _, err := approvalStore.Queue(QueueApprovalInput{SecretID: "secret"}); err == nil {
		t.Fatal("queue without consumer should fail")
	}
	oldRandomRead := randomRead
	randomRead = func([]byte) (int, error) { return 0, errors.New("approval entropy failed") }
	if _, err := approvalStore.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent"}); err == nil || !strings.Contains(err.Error(), "mint approval id") {
		t.Fatalf("queue entropy error = %v", err)
	}
	randomRead = oldRandomRead
	approval, err := approvalStore.Queue(QueueApprovalInput{SecretID: " secret ", RequesterConsumerID: " agent ", TTL: time.Millisecond})
	if err != nil {
		t.Fatalf("queue approval: %v", err)
	}
	if queued.ID != approval.ID || approval.RequestedScope != "session" || approval.RequesterVerifier != "local-daemon-peer" {
		t.Fatalf("queued approval = %+v queued=%+v", approval, queued)
	}
	approvalStore.now = func() time.Time { return now.Add(time.Second) }
	if _, err := approvalStore.PrepareDecision(""); err == nil {
		t.Fatal("empty approval id should fail")
	}
	if _, err := approvalStore.PrepareDecision("missing"); err == nil {
		t.Fatal("missing approval should fail")
	}
	if _, err := approvalStore.PrepareDecision(approval.ID); err == nil {
		t.Fatal("expired approval should fail")
	}
	approvalStore.now = func() time.Time { return now }
	snapshotApproval, err := approvalStore.Queue(QueueApprovalInput{SecretID: "other", RequesterConsumerID: "agent", TTL: time.Millisecond})
	if err != nil {
		t.Fatalf("queue snapshot approval: %v", err)
	}
	approvalStore.now = func() time.Time { return now.Add(time.Second) }
	if snap := approvalStore.Snapshot(); len(snap) != 2 {
		t.Fatalf("expired snapshot length = %+v", snap)
	} else {
		for _, item := range snap {
			if item.ID == snapshotApproval.ID && item.Status != "expired" {
				t.Fatalf("snapshot approval did not expire: %+v", snap)
			}
		}
	}
	freshStore := NewApprovalStore()
	freshStore.now = func() time.Time { return now }
	fresh, err := freshStore.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent"})
	if err != nil {
		t.Fatalf("queue fresh approval: %v", err)
	}
	if _, _, err := freshStore.DecidePrepared("", nil, "", false); err == nil {
		t.Fatal("empty prepared decision id should fail")
	}
	if _, _, err := freshStore.DecidePrepared("missing", nil, "", false); err == nil {
		t.Fatal("missing prepared decision id should fail")
	}
	expiringStore := NewApprovalStore()
	expiringStore.now = func() time.Time { return now }
	expiring, err := expiringStore.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", TTL: time.Millisecond})
	if err != nil {
		t.Fatalf("queue expiring approval: %v", err)
	}
	expiringStore.now = func() time.Time { return now.Add(time.Second) }
	if _, _, err := expiringStore.DecidePrepared(expiring.ID, nil, "", false); err == nil {
		t.Fatal("expired prepared decision should fail")
	}
	decided, changed, err := freshStore.DecidePrepared(fresh.ID, &approvals.Decision{Reason: "no"}, "", false)
	if err != nil || !changed || decided.Status != "denied" || decided.DecidedByActor != "cli" {
		t.Fatalf("denied approval = %+v changed=%t err=%v", decided, changed, err)
	}
	if _, changed, err := freshStore.DecidePrepared(fresh.ID, nil, "actor", true); err != nil || changed {
		t.Fatalf("repeat decision changed=%t err=%v", changed, err)
	}

	sessions := NewSessionStore()
	sessions.now = func() time.Time { return now }
	if _, err := sessions.OpenLease("host", "secret", "", time.Minute, "agent"); err != nil {
		t.Fatalf("open lease: %v", err)
	}
	oldSessionRandomRead := randomRead
	randomRead = func([]byte) (int, error) { return 0, errors.New("lease entropy failed") }
	if _, err := sessions.OpenLease("host", "secret-error", "window", time.Minute, "agent"); err == nil {
		t.Fatal("open lease should propagate session creation error")
	}
	randomRead = oldSessionRandomRead
	lease, err := sessions.OpenLease("host", "secret2", "window", time.Minute, "agent")
	if err != nil {
		t.Fatalf("open second lease: %v", err)
	}
	sessions.processes[10] = processBinding{token: lease.Token}
	if _, found, changed := sessions.RevokeLeaseID(""); found || changed {
		t.Fatal("empty lease id should not be found")
	}
	if _, found, changed := sessions.RevokeLeaseID("missing"); found || changed {
		t.Fatal("missing lease id should not be found")
	}
	if _, found, changed := sessions.RevokeLeaseID(lease.ID); !found || !changed {
		t.Fatalf("revoke lease found=%t changed=%t", found, changed)
	}
	if _, ok := sessions.processes[10]; ok {
		t.Fatal("lease revoke should clear process binding")
	}
	if _, found, changed := sessions.RevokeLeaseID(lease.ID); !found || changed {
		t.Fatalf("repeat revoke found=%t changed=%t", found, changed)
	}
	expired, err := sessions.OpenLease("host", "secret3", "window", time.Millisecond, "agent")
	if err != nil {
		t.Fatalf("open expiring lease: %v", err)
	}
	sessions.now = func() time.Time { return now.Add(time.Second) }
	if _, found, changed := sessions.RevokeLeaseID(expired.ID); !found || changed {
		t.Fatalf("expired revoke found=%t changed=%t", found, changed)
	}
	if got := sessions.RevokeAllForConsumer(""); got != nil {
		t.Fatalf("empty consumer revoke = %+v", got)
	}
	active, err := sessions.OpenLease("host", "secret4", "window", time.Minute, "agent")
	if err != nil {
		t.Fatalf("open active lease: %v", err)
	}
	sessions.now = func() time.Time { return now }
	sessions.processes[11] = processBinding{token: active.Token}
	if revoked := sessions.RevokeAllForConsumer("agent"); len(revoked) == 0 {
		t.Fatal("expected consumer leases revoked")
	}
	if _, ok := sessions.processes[11]; ok {
		t.Fatal("consumer revoke should clear process binding")
	}
	sessions.sessions["internal"] = Session{ID: "internal", Token: "internal", Internal: true, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	sessions.sessions["empty-status"] = Session{ID: "empty-status", Token: "empty-status", RevokedAt: &now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now}
	sessions.sessions["expired-snapshot"] = Session{ID: "expired-snapshot", Token: "expired-snapshot", LeaseSecretID: "secret", ConsumerName: "agent", ExpiresAt: now.Add(-time.Second), LastSeenAt: now.Add(-time.Second)}
	if leases := sessions.LeaseSnapshot(); len(leases) == 0 {
		t.Fatal("expected non-internal leases in snapshot")
	}
	expiredForRevoke, err := sessions.OpenLease("host", "secret5", "window", time.Millisecond, "other")
	if err != nil {
		t.Fatalf("open revoke-all expired lease: %v", err)
	}
	sessions.now = func() time.Time { return now.Add(time.Second) }
	sessions.sessions[expiredForRevoke.Token] = expiredForRevoke
	_ = sessions.RevokeAll()
	sessions.now = func() time.Time { return now }
	expiredForConsumer, err := sessions.OpenLease("host", "secret6", "window", time.Millisecond, "stale")
	if err != nil {
		t.Fatalf("open consumer expired lease: %v", err)
	}
	sessions.now = func() time.Time { return now.Add(time.Second) }
	sessions.sessions[expiredForConsumer.Token] = expiredForConsumer
	if revoked := sessions.RevokeAllForConsumer("stale"); len(revoked) != 0 {
		t.Fatalf("expired consumer revoke = %+v", revoked)
	}
	sessions.now = func() time.Time { return now }
	expiredRegister, err := sessions.Open("host", "/tmp/project", time.Millisecond, false, "agent")
	if err != nil {
		t.Fatalf("open register expired session: %v", err)
	}
	sessions.now = func() time.Time { return now.Add(time.Second) }
	if sessions.RegisterProcess(expiredRegister.Token, 12345) {
		t.Fatal("register process should reject expired session")
	}

	earlier := now.Add(-time.Hour)
	if earliestTime(nil, &now) != &now || earliestTime(&now, nil) != &now || earliestTime(&earlier, &now) != &earlier || earliestTime(&now, &earlier) != &earlier {
		t.Fatal("earliest time branches failed")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/items/api/reveal/inline", nil)
	rec := httptest.NewRecorder()
	called := false
	hmacValidatorMiddleware(nil, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
	if !called {
		t.Fatal("nil validator should call next handler")
	}
	rec = httptest.NewRecorder()
	hmacValidatorMiddleware(nil, nil, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil next status = %d", rec.Code)
	}

	normalized := normalizeHTTPPaths(paths.Paths{HTTPPortFilePath: filepath.Join(t.TempDir(), "portfile")})
	if normalized.HomeDir == "" || normalized.RuntimeDir == "" || normalized.HTTPUnixSocketPath == "" {
		t.Fatalf("normalized paths = %+v", normalized)
	}
	sidecars := httpSidecarPaths(paths.Paths{HomeDir: t.TempDir(), HTTPPortFilePath: "same", HTTPUnixSocketPath: "same"})
	if len(sidecars) != 1 {
		t.Fatalf("deduped sidecars = %+v", sidecars)
	}
	if got := scheduledBackupPath("", now); got != "" {
		t.Fatalf("empty scheduled backup path = %q", got)
	}
	if got := scheduledBackupPath(filepath.Join(t.TempDir(), "manual.hasp-backup"), now); !strings.Contains(got, "HASP-") {
		t.Fatalf("file destination scheduled path = %q", got)
	}
	if got := integrationProfileCatalogPath(paths.Paths{}); got != "" {
		t.Fatalf("empty catalog path = %q", got)
	}
	if got := configStringSlice(12); got != nil {
		t.Fatalf("numeric config string slice = %#v", got)
	}

	server := &rpcServer{}
	server.recordMasterPasswordFailure("caller", now)
	server.recordMasterPasswordFailure("caller", now.Add(time.Second))
	server.masterPasswordRates["caller"] = nil
	for i := 0; i < masterPasswordFailureLimit; i++ {
		server.masterPasswordRates["caller"] = append(server.masterPasswordRates["caller"], now.Add(-masterPasswordFailureWindow+500*time.Millisecond+time.Duration(i)*time.Millisecond))
	}
	if retry := server.masterPasswordRetryAfter("caller", now); retry != time.Second {
		t.Fatalf("minimum retry = %s", retry)
	}
	server.appendDaemonSecurityAudit(audit.EventDeny, map[string]any{"action": "test"})

	broker := &brokerRPC{}
	if err := broker.ListLeases(ListLeasesRequest{}, &ListLeasesResponse{}); err == nil {
		t.Fatal("nil session list leases should fail")
	}
	if err := broker.ListApprovals(ListApprovalsRequest{}, &ListApprovalsResponse{}); err == nil {
		t.Fatal("nil approval list should fail")
	}
	if err := broker.DecideApproval(DecideApprovalRequest{}, &DecideApprovalResponse{}); err == nil {
		t.Fatal("nil approval decide should fail")
	}
	broker.sessions = NewSessionStore()
	if err := broker.RevokeLease(RevokeLeaseRequest{}, &RevokeLeaseResponse{}); err == nil {
		t.Fatal("empty lease revoke should fail")
	}
	broker.matrixInput = func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error) {
		return accessmatrix.Input{}, errors.New("matrix fail")
	}
	if err := broker.AccessMatrix(AccessMatrixRequest{}, &AccessMatrixResponse{}); err == nil {
		t.Fatal("matrix input error should fail")
	}
	if err := broker.SetPolicy(PolicySetRequest{ValidateOnly: true, ReturnValidated: true, Policy: PolicyDocument{Rules: []PolicyRule{{ID: "x", Decision: "allow"}}}}, &PolicyResponse{}); err == nil {
		t.Fatal("invalid validate-only policy should fail")
	}
	var policyReply PolicyResponse
	validPolicy := PolicyDocument{Rules: []PolicyRule{{ID: "allow", Match: PolicyMatch{Consumer: "agent", Secret: "secret", Scope: "window"}, Decision: "allow"}}}
	if err := broker.SetPolicy(PolicySetRequest{ValidateOnly: true, ReturnValidated: true, Policy: validPolicy}, &policyReply); err != nil || len(policyReply.Rules) != 1 {
		t.Fatalf("validate-only policy reply=%+v err=%v", policyReply, err)
	}
	keyring := newHTTPTestKeyring()
	broker.keyring = keyring
	if status := broker.BackupPassphraseStatus(); status.Available || status.Enrolled {
		t.Fatalf("missing passphrase status = %+v", status)
	}
	if _, err := broker.SetBackupPassphrase(BackupPassphraseRequest{}); err == nil {
		t.Fatal("empty backup passphrase should fail")
	}
	if _, err := broker.SetBackupPassphrase(BackupPassphraseRequest{Passphrase: "secret-passphrase"}); err != nil {
		t.Fatalf("set backup passphrase: %v", err)
	}
	if status := broker.BackupPassphraseStatus(); !status.Enrolled || !status.Available {
		t.Fatalf("enrolled passphrase status = %+v", status)
	}
	if passphrase, err := broker.backupPassphraseFromKeyring(); err != nil || passphrase != "secret-passphrase" {
		t.Fatalf("backup passphrase = %q err=%v", passphrase, err)
	}
	if _, err := broker.DeleteBackupPassphrase(); err != nil {
		t.Fatalf("delete backup passphrase: %v", err)
	}
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "")
	t.Setenv("USERNAME", "")
	if account := backupPassphraseAccount(); account != "default" {
		t.Fatalf("backup account fallback = %q", account)
	}
}

func TestRuntimeDefaultVaultHelpersCoverage(t *testing.T) {
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:    home,
		StatePath:  filepath.Join(home, "vault.json"),
		AuditPath:  filepath.Join(home, "audit.jsonl"),
		SocketPath: filepath.Join(home, "hasp.sock"),
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
	item, err := handle.UpsertItem("api", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Tags: []string{"test"}})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertAgentConsumer(store.AgentConsumer{Name: "Agent", AgentID: "agent", ConfigPath: filepath.Join(home, "agent.json")}); err != nil {
		t.Fatalf("register agent: %v", err)
	}

	if _, err := defaultRevealItem(context.Background(), runtimePaths, "api"); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("default reveal without convenience err=%v", err)
	}
	if err := defaultValidateVaultUnlock(context.Background(), runtimePaths); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("default validate without convenience err=%v", err)
	}
	input, err := defaultAccessMatrixInput(context.Background(), runtimePaths, nil)
	if err != nil || len(input.Items) == 0 || len(input.AgentConsumers) == 0 {
		t.Fatalf("default matrix input=%+v err=%v", input, err)
	}
	openedHandle, err := openRuntimeVaultHandle(context.Background(), runtimePaths)
	if err != nil {
		t.Fatalf("open runtime vault handle: %v", err)
	}
	noSessions := accessMatrixInputFromHandle(openedHandle, nil)
	if len(noSessions.Sessions) != 0 || len(noSessions.Leases) != 0 {
		t.Fatalf("nil sessions matrix input = %+v", noSessions)
	}
	sessions := NewSessionStore()
	if _, err := sessions.Open("host", home, time.Minute, false, "agent"); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if _, err := sessions.OpenLease("host", item.ID, "read", time.Minute, "agent"); err != nil {
		t.Fatalf("open lease: %v", err)
	}
	withSessions := accessMatrixInputFromHandle(openedHandle, sessions)
	if len(withSessions.Sessions) == 0 || len(withSessions.Leases) == 0 {
		t.Fatalf("session matrix input = %+v", withSessions)
	}

	oldNewStoreForPaths := newStoreForPaths
	oldOpenConvenience := storeOpenWithConvenienceUnlock
	oldRevealFind := revealFind
	oldRequirement := haspAppDesignatedRequirement
	oldLoadHMAC := loadProvisionedHMACKey
	oldHMACRandom := httpHMACRandomRead
	oldGoTestBinary := goTestBinary
	t.Cleanup(func() {
		newStoreForPaths = oldNewStoreForPaths
		storeOpenWithConvenienceUnlock = oldOpenConvenience
		revealFind = oldRevealFind
		haspAppDesignatedRequirement = oldRequirement
		loadProvisionedHMACKey = oldLoadHMAC
		httpHMACRandomRead = oldHMACRandom
		goTestBinary = oldGoTestBinary
	})
	newStoreForPaths = func(store.Keyring, paths.Paths) (*store.Store, error) { return nil, errors.New("new store failed") }
	if _, err := defaultRevealItem(context.Background(), runtimePaths, "api"); err == nil {
		t.Fatal("default reveal should propagate store creation failure")
	}
	if err := defaultValidateVaultUnlock(context.Background(), runtimePaths); err == nil {
		t.Fatal("default validate should propagate store creation failure")
	}
	if _, err := defaultAccessMatrixInput(context.Background(), runtimePaths, nil); err == nil {
		t.Fatal("default matrix should propagate store creation failure")
	}
	if _, err := openRuntimeVaultHandle(context.Background(), runtimePaths); err == nil {
		t.Fatal("open runtime handle should propagate store creation failure")
	}
	newStoreForPaths = oldNewStoreForPaths
	storeOpenWithConvenienceUnlock = func(*store.Store, context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	revealFind = func(*store.Handle, string) (revealcore.Payload, error) {
		return revealcore.Payload{ID: "api", Name: "api", Value: []byte("secret"), UpdatedAt: time.Now().UTC()}, nil
	}
	if payload, err := defaultRevealItem(context.Background(), runtimePaths, "api"); err != nil || payload.ID != "api" {
		t.Fatalf("seamed default reveal payload=%+v err=%v", payload, err)
	}
	if err := defaultValidateVaultUnlock(context.Background(), runtimePaths); err != nil {
		t.Fatalf("seamed default validate: %v", err)
	}
	storeOpenWithConvenienceUnlock = oldOpenConvenience
	revealFind = oldRevealFind

	haspAppDesignatedRequirement = func(string) (string, error) { return "", errors.New("requirement failed") }
	if _, err := newHASPAppAttestor(); err == nil {
		t.Fatal("attestor should propagate designated requirement failure")
	}
	haspAppDesignatedRequirement = oldRequirement
	loadProvisionedHMACKey = func(store.Keyring) ([]byte, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	}
	if key, err := defaultHTTPHMACKey(context.Background()); err != nil || string(key) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("provisioned hmac key=%q err=%v", key, err)
	}
	loadProvisionedHMACKey = func(store.Keyring) ([]byte, error) { return nil, errors.New("missing key") }
	httpHMACRandomRead = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if _, err := defaultHTTPHMACKey(context.Background()); err == nil {
		t.Fatal("test hmac entropy error should propagate")
	}
	httpHMACRandomRead = oldHMACRandom
	goTestBinary = func() bool { return false }
	t.Setenv(paths.EnvTest, "")
	if _, err := defaultHTTPHMACKey(context.Background()); err == nil {
		t.Fatal("non-test missing hmac key should propagate")
	}
	if normalized := normalizeHTTPPaths(paths.Paths{}); normalized.HomeDir == "" || normalized.HTTPPortFilePath == "" {
		t.Fatalf("default normalized paths = %+v", normalized)
	}
}

func TestRuntimeBrokerVaultBackupsAndIntegrationsCoverage(t *testing.T) {
	password := "correct horse battery staple"
	t.Setenv("HASP_MASTER_PASSWORD", password)
	home := t.TempDir()
	runtimePaths := paths.Paths{
		HomeDir:   home,
		StatePath: filepath.Join(home, "vault.json"),
		AuditPath: filepath.Join(home, "audit.jsonl"),
	}
	vaultStore, err := store.NewForPaths(newHTTPTestKeyring(), runtimePaths)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), password); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), password)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertAgentConsumer(store.AgentConsumer{Name: "Agent", AgentID: "agent", ConfigPath: filepath.Join(home, "agent.json")}); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}
	if _, err := handle.UpsertItem("secret", store.ItemKindKV, []byte("value"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	broker := &brokerRPC{
		paths:      runtimePaths,
		sessions:   NewSessionStore(),
		approvals:  NewApprovalStore(),
		events:     newRuntimeEventHub(),
		auditState: newAuditState(nil),
		keyring:    newHTTPTestKeyring(),
	}
	if err := broker.RevokeAllSessions(RevokeAllSessionsRequest{}, &RevokeAllSessionsResponse{}); err != nil {
		t.Fatalf("revoke all sessions: %v", err)
	}
	var leasesReply ListLeasesResponse
	if err := broker.ListLeases(ListLeasesRequest{ExpiringInSeconds: 60}, &leasesReply); err != nil {
		t.Fatalf("list leases with expiring: %v", err)
	}
	var matrixReply AccessMatrixResponse
	if err := broker.AccessMatrix(AccessMatrixRequest{}, &matrixReply); err != nil {
		t.Fatalf("default matrix: %v", err)
	}
	if err := broker.AccessMatrix(AccessMatrixRequest{Source: "invalid"}, &matrixReply); err == nil {
		t.Fatal("invalid matrix source should fail")
	}
	var policyReply PolicyResponse
	if err := broker.Policy(PolicyGetRequest{}, &policyReply); err != nil {
		t.Fatalf("policy: %v", err)
	}
	var configReply ConfigResponse
	if err := broker.Config(ConfigGetRequest{}, &configReply); err != nil {
		t.Fatalf("config: %v", err)
	}
	var configValueReply ConfigValueResponse
	if err := broker.SetConfig(ConfigSetRequest{Key: "vault.idle_relock_s", Value: 120, Actor: "test"}, &configValueReply); err != nil {
		t.Fatalf("set config: %v", err)
	}
	badAuditServer := &rpcServer{paths: runtimePaths, audit: audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()}), auditState: newAuditState(nil)}
	if _, err := badAuditServer.secretsListSnapshot(context.Background()); err == nil {
		t.Fatal("secrets list should propagate audit read errors")
	}

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := broker.Backup(BackupRequest{DestinationPath: filepath.Join(blocker, "backup"), Passphrase: "backup passphrase"}, &BackupResponse{}); err == nil {
		t.Fatal("backup export should fail when parent is a file")
	}
	oldBackupStatus := backupStatusForFile
	t.Cleanup(func() { backupStatusForFile = oldBackupStatus })
	backupStatusForFile = func(string) (store.BackupSignatureStatus, error) {
		return store.BackupSignatureStatus{}, errors.New("signature failed")
	}
	if err := broker.Backup(BackupRequest{DestinationPath: filepath.Join(t.TempDir(), "backup"), Passphrase: "backup passphrase"}, &BackupResponse{}); err == nil {
		t.Fatal("backup signature failure should propagate")
	}
	backupStatusForFile = oldBackupStatus
	oldPrune := pruneBackupDirectory
	t.Cleanup(func() { pruneBackupDirectory = oldPrune })
	pruneBackupDirectory = func(string, int, string) error { return errors.New("prune failed") }
	if err := broker.Backup(BackupRequest{DestinationPath: filepath.Join(t.TempDir(), "backup"), Passphrase: "backup passphrase"}, &BackupResponse{}); err == nil {
		t.Fatal("backup prune failure should propagate")
	}
	pruneBackupDirectory = oldPrune

	broker.keyring = failingSetKeyring{Keyring: newHTTPTestKeyring()}
	if _, err := broker.SetBackupPassphrase(BackupPassphraseRequest{Passphrase: "secret"}); err == nil {
		t.Fatal("backup passphrase set failure should propagate")
	}
	broker.keyring = failingDeleteKeyring{Keyring: newHTTPTestKeyring()}
	if _, err := broker.DeleteBackupPassphrase(); err == nil {
		t.Fatal("backup passphrase delete failure should propagate")
	}
	broker.keyring = blankGetKeyring{Keyring: newHTTPTestKeyring()}
	if _, err := broker.backupPassphraseFromKeyring(); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("blank backup passphrase err=%v", err)
	}
	if err := broker.runScheduledBackupOnce(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("missing scheduled passphrase should be ignored: %v", err)
	}
	oldNewStoreForPaths := newStoreForPaths
	newStoreForPaths = func(store.Keyring, paths.Paths) (*store.Store, error) {
		return nil, errors.New("scheduled open failed")
	}
	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup passphrase")
	if err := broker.runScheduledBackupOnce(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("scheduled backup should propagate vault open errors")
	}
	newStoreForPaths = oldNewStoreForPaths

	if err := broker.runScheduledBackupOnce(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("default disabled scheduled backup: %v", err)
	}
	if _, err := handle.SetConfigValue("backup.schedule", "daily", "test"); err != nil {
		t.Fatalf("set schedule: %v", err)
	}
	if err := broker.runScheduledBackupOnce(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("blank destination scheduled backup: %v", err)
	}
	if _, err := handle.SetConfigValue("backup.destination_path", t.TempDir(), "test"); err != nil {
		t.Fatalf("set destination: %v", err)
	}
	if _, err := handle.SetConfigValue("backup.last_backup_at", time.Now().UTC().Format(time.RFC3339), "test"); err != nil {
		t.Fatalf("set last backup: %v", err)
	}
	if err := broker.runScheduledBackupOnce(context.Background(), time.Now().UTC()); err != nil {
		t.Fatalf("not due scheduled backup: %v", err)
	}
	oldTick := backupSchedulerTick
	backupSchedulerTick = time.Millisecond
	t.Cleanup(func() { backupSchedulerTick = oldTick })
	tickCtx, cancelTick := context.WithCancel(context.Background())
	tickDone := make(chan struct{})
	go func() {
		broker.runScheduledBackups(tickCtx)
		close(tickDone)
	}()
	time.Sleep(3 * time.Millisecond)
	cancelTick()
	select {
	case <-tickDone:
	case <-time.After(time.Second):
		t.Fatal("scheduled backup loop did not stop")
	}

	if _, err := handle.SetConfigValue("integrations.disabled_targets", []any{"mcp"}, "test"); err != nil {
		t.Fatalf("set disabled integrations: %v", err)
	}
	var list IntegrationListResponse
	if err := broker.Integrations(IntegrationGetRequest{}, &list); err != nil {
		t.Fatalf("integrations: %v", err)
	}
	var catalog IntegrationProfilesResponse
	if err := broker.IntegrationProfileCatalog(IntegrationGetRequest{}, &catalog); err != nil {
		t.Fatalf("profile catalog: %v", err)
	}
	if err := broker.IntegrationProfiles(IntegrationProfilesRequest{TargetID: "mcp"}, &catalog); err == nil {
		t.Fatal("disabled integration profiles should look missing")
	}
	if err := broker.DoctorIntegration(IntegrationDoctorRPCRequest{TargetID: "mcp"}, &IntegrationDoctorResponse{}); err == nil {
		t.Fatal("disabled integration doctor should look missing")
	}
	if err := broker.CreateIntegrationProfile(IntegrationProfileMutationRPCRequest{Body: IntegrationProfileMutationRequest{TargetID: "mcp", ID: "custom", Name: "Custom", TargetPattern: "hasp mcp", Scope: "agent"}}, &IntegrationProfileMutationResponse{}); err == nil {
		t.Fatal("disabled create profile should fail")
	}
	if err := broker.UpdateIntegrationProfile(IntegrationProfileMutationRPCRequest{TargetID: "mcp", ProfileID: "custom"}, &IntegrationProfileMutationResponse{}); err == nil {
		t.Fatal("disabled update profile should fail")
	}
	if err := broker.DeleteIntegrationProfile(IntegrationProfileMutationRPCRequest{TargetID: "mcp", ProfileID: "custom"}, &IntegrationProfileMutationResponse{}); err == nil {
		t.Fatal("disabled delete profile should fail")
	}
	badHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(badHome, "integrations.profiles.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad catalog: %v", err)
	}
	badBroker := &brokerRPC{paths: paths.Paths{HomeDir: badHome}}
	if err := badBroker.Integrations(IntegrationGetRequest{}, &IntegrationListResponse{}); err == nil {
		t.Fatal("bad catalog should fail integrations")
	}
	if err := badBroker.IntegrationProfileCatalog(IntegrationGetRequest{}, &IntegrationProfilesResponse{}); err == nil {
		t.Fatal("bad catalog should fail profile catalog")
	}
	if err := badBroker.CreateIntegrationProfile(IntegrationProfileMutationRPCRequest{Body: IntegrationProfileMutationRequest{TargetID: "mcp", ID: "custom", Name: "Custom", TargetPattern: "hasp mcp", Scope: "agent"}}, &IntegrationProfileMutationResponse{}); err == nil {
		t.Fatal("bad catalog should fail create profile")
	}
	if err := badBroker.DeleteIntegrationProfile(IntegrationProfileMutationRPCRequest{TargetID: "mcp", ProfileID: "custom", IfMatch: "version"}, &IntegrationProfileMutationResponse{}); err == nil {
		t.Fatal("bad catalog should fail delete profile")
	}
	if disabled := badBroker.disabledIntegrationTargets(); len(disabled) != 0 {
		t.Fatalf("bad broker disabled integrations = %+v", disabled)
	}

	decisionBroker := &brokerRPC{approvals: NewApprovalStore(), sessions: NewSessionStore(), events: newRuntimeEventHub()}
	now := time.Now().UTC()
	decisionBroker.approvals.now = func() time.Time { return now }
	approval, err := decisionBroker.approvals.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", TTL: time.Minute})
	if err != nil {
		t.Fatalf("queue decision approval: %v", err)
	}
	for _, req := range []DecideApprovalRequest{
		{ApprovalID: approval.ID, Decision: "grant", Reason: "because", HoldDurationMS: 1500, AuthMethod: "touch-id"},
		{ApprovalID: approval.ID, Decision: "grant", HoldDurationMS: 1499, AuthMethod: "touch-id"},
		{ApprovalID: approval.ID, Decision: "grant", HoldDurationMS: 1500, AuthMethod: "password"},
		{ApprovalID: approval.ID, Decision: "deny", GrantedTTLS: 60},
		{ApprovalID: approval.ID, Decision: "maybe"},
	} {
		if err := decisionBroker.DecideApproval(req, &DecideApprovalResponse{}); err == nil {
			t.Fatalf("decision %+v should fail", req)
		}
	}
	if err := decisionBroker.DecideApproval(DecideApprovalRequest{ApprovalID: approval.ID, Decision: "grant", HoldDurationMS: 1500, AuthMethod: "touch-id"}, &DecideApprovalResponse{}); !errors.Is(err, errVaultLocked) {
		t.Fatalf("locked grant err=%v", err)
	}
	if err := decisionBroker.DecideApproval(DecideApprovalRequest{ApprovalID: "missing", Decision: "deny"}, &DecideApprovalResponse{}); err == nil {
		t.Fatal("missing approval decision should fail")
	}
	if _, err := decisionBroker.sessions.Open("host", home, time.Minute, false, "agent"); err != nil {
		t.Fatalf("open decision session: %v", err)
	}
	grantApproval, err := decisionBroker.approvals.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", RequestedTTLS: int((DefaultSessionTTL + time.Hour).Seconds()), TTL: time.Minute})
	if err != nil {
		t.Fatalf("queue grant approval: %v", err)
	}
	grantApproval.RequestedScope = ""
	decisionBroker.approvals.approvals[grantApproval.ID] = grantApproval
	var decisionReply DecideApprovalResponse
	if err := decisionBroker.DecideApproval(DecideApprovalRequest{ApprovalID: grantApproval.ID, Decision: "grant", HoldDurationMS: 1500, AuthMethod: "touch-id"}, &decisionReply); err != nil || decisionReply.LeaseID == "" {
		t.Fatalf("grant decision reply=%+v err=%v", decisionReply, err)
	}
	errorApproval, err := decisionBroker.approvals.Queue(QueueApprovalInput{SecretID: "secret", RequesterConsumerID: "agent", TTL: time.Minute})
	if err != nil {
		t.Fatalf("queue error approval: %v", err)
	}
	oldRandomRead := randomRead
	randomRead = func([]byte) (int, error) { return 0, errors.New("session entropy failed") }
	if err := decisionBroker.DecideApproval(DecideApprovalRequest{ApprovalID: errorApproval.ID, Decision: "grant", HoldDurationMS: 1500, AuthMethod: "touch-id"}, &DecideApprovalResponse{}); err == nil {
		t.Fatal("grant decision should propagate session creation error")
	}
	randomRead = oldRandomRead
	if err := decisionBroker.RevokeLease(RevokeLeaseRequest{LeaseIDs: []string{"missing"}}, &RevokeLeaseResponse{}); err != nil {
		t.Fatalf("missing lease id bulk revoke: %v", err)
	}
}

type failingSetKeyring struct{ store.Keyring }

func (failingSetKeyring) Set(context.Context, string, string, string) error {
	return errors.New("set failed")
}

type failingDeleteKeyring struct{ store.Keyring }

func (failingDeleteKeyring) Delete(string, string) error {
	return errors.New("delete failed")
}

type blankGetKeyring struct{ store.Keyring }

func (blankGetKeyring) Get(string, string) (string, error) {
	return "   ", nil
}

func httpapiWithPeerPID(ctx context.Context, pid int) context.Context {
	return httpapi.WithPeerPID(ctx, pid)
}

type nonFlushingRecorder struct {
	bytes.Buffer
	header http.Header
	code   int
}

func (r *nonFlushingRecorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}

func (r *nonFlushingRecorder) WriteHeader(code int) { r.code = code }
