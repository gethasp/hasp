package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type failingReadCloser struct{}

func (f failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read fail") }
func (f failingReadCloser) Close() error             { return nil }

const daemonHMACBodyLimit = 1 << 20

type readTrackingBody struct {
	remaining  int64
	readCalls  int
	bytesRead  int64
	failOnRead bool
}

func (b *readTrackingBody) Read(p []byte) (int, error) {
	b.readCalls++
	if b.failOnRead {
		return 0, errors.New("body read should not happen")
	}
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > b.remaining {
		n = int(b.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	b.remaining -= int64(n)
	b.bytesRead += int64(n)
	return n, nil
}

func (b *readTrackingBody) Close() error { return nil }

func TestValidatorAcceptsSignedRequestAndRestoresBody(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x42}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	body := []byte(`{"value":"ok"}`)
	req := signedRequest(t, key, now, "00112233445566778899aabbccddeeff", http.MethodPost, "/v1/items", "", body)

	if err := validator.Validate(req); err != nil {
		t.Fatalf("validate: %v", err)
	}
	gotBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("restored body = %q, want %q", gotBody, body)
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErrorEnvelope(rec, http.StatusTeapot, "short", "Short", "detail")
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"code":"short"`) || !strings.Contains(body, `"detail":"detail"`) {
		t.Fatalf("body = %s", body)
	}
}

func TestWritePublicErrorEnvelopeUsesGenericDetail(t *testing.T) {
	rec := httptest.NewRecorder()
	WritePublicErrorEnvelope(rec, http.StatusUnauthorized, "unauthorized", "Unauthorized")
	if body := rec.Body.String(); !strings.Contains(body, `"detail":"Unauthorized"`) || strings.Contains(body, "missing HASP-Date header") {
		t.Fatalf("body = %s", body)
	}
}

func TestValidatorRejectsReplay(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x11}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
		NonceTTL:        time.Minute,
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req1 := signedRequest(t, key, now, "ffeeddccbbaa99887766554433221100", http.MethodGet, "/v1/vault/status", "", nil)
	if err := validator.Validate(req1); err != nil {
		t.Fatalf("first validate: %v", err)
	}

	req2 := signedRequest(t, key, now, "ffeeddccbbaa99887766554433221100", http.MethodGet, "/v1/vault/status", "", nil)
	err = validator.Validate(req2)
	if !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("expected nonce replay rejection, got %v", err)
	}
}

func TestValidatorMiddlewareRedactsFailureDetails(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x21}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	rec := httptest.NewRecorder()
	validator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next should not run")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"detail":"Unauthorized"`) || strings.Contains(body, ErrMissingDateHeader.Error()) {
		t.Fatalf("unauthorized body = %s", body)
	}

	oversizedBody := &readTrackingBody{remaining: daemonHMACBodyLimit + 1, failOnRead: true}
	oversizedReq := requestWithValidLookingHeaders(t, now, "abcdefabcdefabcdefabcdefabcdefc0", http.MethodPost, "/v1/config/value", oversizedBody)
	oversizedReq.ContentLength = daemonHMACBodyLimit + 1

	rec = httptest.NewRecorder()
	validator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next should not run")
	})).ServeHTTP(rec, oversizedReq)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"detail":"Request Entity Too Large"`) || strings.Contains(body, ErrRequestBodyTooLarge.Error()) {
		t.Fatalf("oversized body = %s", body)
	}
}

func TestValidatorRejectsClockSkew(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x22}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req := signedRequest(t, key, now.Add(-61*time.Second), "1234567890abcdef1234567890abcdef", http.MethodGet, "/v1/leases", "", nil)
	err = validator.Validate(req)
	if !errors.Is(err, ErrDateSkewExceeded) {
		t.Fatalf("expected skew rejection, got %v", err)
	}
}

func TestValidatorAcceptsBoundaryClockSkew(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x24}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	for nonce, when := range map[string]time.Time{
		"00112233445566778899aabbccddeeff": now.Add(-60 * time.Second),
		"ffeeddccbbaa99887766554433221100": now.Add(60 * time.Second),
	} {
		req := signedRequest(t, key, when, nonce, http.MethodGet, "/v1/leases", "", nil)
		if err := validator.Validate(req); err != nil {
			t.Fatalf("boundary skew should validate: %v", err)
		}
	}
}

func TestValidatorSignsRawQuery(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x25}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req := signedRequest(t, key, now, "1234567890abcdef1234567890abcdef", http.MethodGet, "/v1/access/matrix", "project=a", nil)
	req.URL.RawQuery = "project=b"
	err = validator.Validate(req)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected query tamper signature rejection, got %v", err)
	}
}

func TestSwiftDaemonClientRoundTripAgainstServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	key := bytes.Repeat([]byte{0x42}, 32)
	validator, err := NewValidator(key, ValidatorOptions{})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"_schema":1,"vault":{"state":"unlocked","idle_relock_in_s":600},"leases":{"active_count":2,"expiring_soon":4},"approvals":{"pending_count":3,"oldest_age_s":0},"audit":{"chain_ok":true},"integrations":{"ok_count":0,"degraded_count":0,"known":false},"daemon":{"uptime_s":60,"version":"dev","http_listener":{"host":"127.0.0.1","port":49152}}}`)
	})
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "topics=vault.locked" {
			t.Fatalf("unexpected events query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: vault.locked\ndata: {\"cause\":\"manual\"}\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, ": still-open\n\n")
	})

	home := t.TempDir()
	server, err := NewServer(paths.Paths{
		HomeDir:          home,
		HTTPPortFilePath: filepath.Join(home, "daemon.http.port"),
	}, Options{
		Handler:   mux,
		Validator: validator,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(serveCtx)
	}()
	defer func() {
		stopServe()
		if err := <-errCh; err != nil {
			t.Fatalf("serve: %v", err)
		}
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
	baseURL := "http://127.0.0.1:" + strconv.Itoa(server.Ports().V4)
	cmd := exec.CommandContext(
		ctx,
		"swift",
		"run",
		"--package-path",
		macosPackage,
		"daemonclient-smoke",
		"--base-url",
		baseURL,
		"--key-hex",
		hex.EncodeToString(key),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("swift daemon client smoke failed: %v\n%s", err, string(output))
	}

	cmd = exec.CommandContext(
		ctx,
		"swift",
		"run",
		"--package-path",
		macosPackage,
		"daemonclient-smoke",
		"--base-url",
		baseURL,
		"--key-hex",
		hex.EncodeToString(key),
		"--events-topic",
		"vault.locked",
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("swift daemon client SSE smoke failed: %v\n%s", err, string(output))
	}
}

func TestValidatorRejectsMalformedAuthShapes(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x26}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	tests := []struct {
		name string
		edit func(*http.Request)
		want error
	}{
		{
			name: "missing date",
			edit: func(req *http.Request) {
				req.Header.Del(HeaderDate)
			},
			want: ErrMissingDateHeader,
		},
		{
			name: "bad date",
			edit: func(req *http.Request) {
				req.Header.Set(HeaderDate, "yesterday")
			},
			want: ErrMalformedDateHeader,
		},
		{
			name: "missing nonce",
			edit: func(req *http.Request) {
				req.Header.Del(HeaderNonce)
			},
			want: ErrMissingNonceHeader,
		},
		{
			name: "bad nonce",
			edit: func(req *http.Request) {
				req.Header.Set(HeaderNonce, "nothex")
			},
			want: ErrMalformedNonceHeader,
		},
		{
			name: "missing authorization",
			edit: func(req *http.Request) {
				req.Header.Del("Authorization")
			},
			want: ErrMissingAuthorization,
		},
		{
			name: "bad authorization",
			edit: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer nope")
			},
			want: ErrMalformedAuthorization,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefab", http.MethodGet, "/v1/items", "", nil)
			tc.edit(req)
			if err := validator.Validate(req); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestValidatorRejectsBodyTamper(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x33}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req := signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefab", http.MethodPost, "/v1/items/abc/reveal", "", []byte(`{"mode":"inline"}`))
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"mode":"clipboard"}`)))

	err = validator.Validate(req)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected signature rejection, got %v", err)
	}
}

func TestValidatorRejectsOversizedContentLengthBeforeReadingBody(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x34}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	body := &readTrackingBody{remaining: daemonHMACBodyLimit + 1, failOnRead: true}
	req := requestWithValidLookingHeaders(t, now, "abcdefabcdefabcdefabcdefabcdefaf", http.MethodPost, "/v1/config/value", body)
	req.ContentLength = daemonHMACBodyLimit + 1

	err = validator.Validate(req)
	if err == nil {
		t.Fatal("expected oversized content-length rejection")
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("oversized content-length should fail before signature validation: %v", err)
	}
	if body.readCalls != 0 {
		t.Fatalf("oversized content-length should reject before reading body, read calls=%d", body.readCalls)
	}
}

func TestValidatorRejectsUnknownLengthBodiesAfterBoundedHashing(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x35}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	body := &readTrackingBody{remaining: 2 * daemonHMACBodyLimit}
	req := requestWithValidLookingHeaders(t, now, "abcdefabcdefabcdefabcdefabcdefb0", http.MethodPost, "/v1/backups", body)
	req.ContentLength = -1

	err = validator.Validate(req)
	if err == nil {
		t.Fatal("expected oversized unknown-length body rejection")
	}
	if errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("oversized unknown-length body should fail before signature validation: %v", err)
	}
	if body.bytesRead > daemonHMACBodyLimit+1 {
		t.Fatalf("unknown-length body should be bounded while hashing, read %d bytes", body.bytesRead)
	}
}

func TestValidatorMiddlewarePreservesBoundarySizedBodiesForHandlers(t *testing.T) {
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x36}, 32)

	validator, err := NewValidator(key, ValidatorOptions{
		AllowedDateSkew: DefaultAllowedDateSkew,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	body := bytes.Repeat([]byte{'a'}, daemonHMACBodyLimit)
	req := signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefb1", http.MethodPost, "/v1/backups", "", body)

	rec := httptest.NewRecorder()
	validator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatalf("read handler body: %v", readErr)
		}
		if !bytes.Equal(gotBody, body) {
			t.Fatalf("handler body length=%d want %d", len(gotBody), len(body))
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("boundary-sized signed request status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestValidatorResidualBranches(t *testing.T) {
	if _, err := NewValidator(nil, ValidatorOptions{}); err == nil {
		t.Fatal("empty validator key should fail")
	}
	now := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x44}, 32)
	validator, err := NewValidator(key, ValidatorOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new default validator: %v", err)
	}
	if validator.allowedDateSkew != DefaultAllowedDateSkew || validator.nonces.ttl != DefaultNonceTTL {
		t.Fatalf("validator defaults skew=%s ttl=%s", validator.allowedDateSkew, validator.nonces.ttl)
	}
	if err := validator.Validate(nil); err == nil {
		t.Fatal("nil request should fail validation")
	}
	for _, header := range []string{
		AuthorizationScheme + " sig=",
		AuthorizationScheme + " sig=%%%bad",
		AuthorizationScheme + " sig=" + base64.StdEncoding.EncodeToString([]byte("short")),
	} {
		if _, err := parseAuthorizationHeader(header); err == nil {
			t.Fatalf("malformed authorization %q should fail", header)
		}
	}
	req := signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefac", http.MethodPost, "/v1/items", "", []byte("body"))
	req.Body = failingReadCloser{}
	if err := validator.Validate(req); err == nil || !strings.Contains(err.Error(), "hash request body") {
		t.Fatalf("body read failure = %v", err)
	}
	if got := requestTarget(nil); got != "" {
		t.Fatalf("nil request target = %q", got)
	}
	if got := requestTarget(&url.URL{}); got != "/" {
		t.Fatalf("empty URL target = %q", got)
	}
	nilBodyReq := httptest.NewRequest(http.MethodPost, "/", nil)
	nilBodyReq.Body = nil
	emptyHash, err := requestBodyHash(nilBodyReq, DefaultMaxBodyBytes)
	if err != nil {
		t.Fatalf("nil request body hash: %v", err)
	}
	sum := sha256.Sum256(nil)
	if emptyHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("nil body hash = %q", emptyHash)
	}
	cache := nonceCache{
		entries: map[string]time.Time{"old": now.Add(-2 * time.Minute)},
		ttl:     time.Minute,
		now:     func() time.Time { return now },
	}
	if err := cache.remember("new"); err != nil {
		t.Fatalf("remember with stale entry: %v", err)
	}
	if _, ok := cache.entries["old"]; ok {
		t.Fatalf("stale nonce was not pruned: %+v", cache.entries)
	}

	rec := httptest.NewRecorder()
	validator.Middleware(nil).ServeHTTP(rec, signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefad", http.MethodGet, "/", "", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil middleware next status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	called := false
	validator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, signedRequest(t, key, now, "abcdefabcdefabcdefabcdefabcdefae", http.MethodGet, "/", "", nil))
	if !called {
		t.Fatal("middleware did not call next on valid request")
	}
	rec = httptest.NewRecorder()
	validator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next should not run") })).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("middleware invalid status = %d", rec.Code)
	}
}

func signedRequest(t *testing.T, key []byte, when time.Time, nonce, method, path, rawQuery string, body []byte) *http.Request {
	t.Helper()

	target := "http://localhost" + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	dateValue := when.UTC().Format(time.RFC3339Nano)
	bodyHash := sha256.Sum256(body)
	signature := computeSignature(
		key,
		dateValue,
		nonce,
		method,
		requestTarget(req.URL),
		hex.EncodeToString(bodyHash[:]),
	)
	req.Header.Set(HeaderDate, dateValue)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set("Authorization", AuthorizationScheme+" sig="+base64.StdEncoding.EncodeToString(signature))
	return req
}

func requestWithValidLookingHeaders(t *testing.T, when time.Time, nonce, method, path string, body io.ReadCloser) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, "http://localhost"+path, nil)
	req.Body = body
	req.Header.Set(HeaderDate, when.UTC().Format(time.RFC3339Nano))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set("Authorization", AuthorizationScheme+" sig="+base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	return req
}
