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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

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
