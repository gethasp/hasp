package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/httpapi"
)

// TestRequireLocalAdminTransport pins hasp-2dzp: vault-mutating admin operations
// are allowed over the unix socket always, and over TCP only when the HMAC key is
// per-app ACL-protected (Darwin). When unprotected (Linux), TCP admin is rejected.
func TestRequireLocalAdminTransport(t *testing.T) {
	orig := adminOverTCPAllowed
	t.Cleanup(func() { adminOverTCPAllowed = orig })

	// Unprotected key (e.g. Linux): TCP admin must be rejected.
	adminOverTCPAllowed = func() bool { return false }
	rec := httptest.NewRecorder()
	if requireLocalAdminTransport(rec, httptest.NewRequest(http.MethodPost, "/v1/vault/unlock", nil)) {
		t.Fatal("TCP admin must be rejected when the HMAC key is unprotected")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rejection status = %d, want 403", rec.Code)
	}

	// ...but the unix socket is always allowed.
	r := httptest.NewRequest(http.MethodPost, "/v1/vault/unlock", nil)
	r = r.WithContext(httpapi.WithUnixTransport(r.Context()))
	if !requireLocalAdminTransport(httptest.NewRecorder(), r) {
		t.Fatal("unix-socket admin must be allowed")
	}

	// Protected key (Darwin): TCP admin is allowed (only the signed app can forge).
	adminOverTCPAllowed = func() bool { return true }
	if !requireLocalAdminTransport(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/vault/unlock", nil)) {
		t.Fatal("TCP admin must be allowed when the HMAC key is ACL-protected")
	}
}
