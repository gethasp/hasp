//go:build !darwin || !cgo || hasp_no_attestation || hasp_test_fastkdf

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyPIDDesignatedRequirementUnavailableWithoutPlatformAttestation(t *testing.T) {
	err := verifyPIDDesignatedRequirement(1234, `identifier "com.gethasp.hasp.HASP"`)
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func TestRevealAttestationMiddlewareAllowsClipboardWhenPlatformAttestationUnavailable(t *testing.T) {
	nextCalled := false
	handler := RevealAttestationMiddleware(
		fakeAttestor{err: ErrAttestationUnavailable},
		func(*http.Request) (int, error) { return 1234, nil },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/clipboard", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.Code)
	}
	if !nextCalled {
		t.Fatal("next handler should run for clipboard fallback")
	}
}

func TestRevealAttestationMiddlewareRejectsInlineWhenPlatformAttestationUnavailable(t *testing.T) {
	handler := RevealAttestationMiddleware(
		fakeAttestor{err: ErrAttestationUnavailable},
		func(*http.Request) (int, error) { return 1234, nil },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/inline", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
}
