package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDesignatedRequirementAttestorRequiresRequirement(t *testing.T) {
	attestor, err := NewDesignatedRequirementAttestor("   ")
	if err == nil {
		t.Fatal("expected empty designated requirement rejection")
	}
	if attestor != nil {
		t.Fatal("attestor should be nil on empty requirement")
	}
}

func TestHASPAppDesignatedRequirementMatchesSpec(t *testing.T) {
	requirement, err := HASPAppDesignatedRequirement(" TEAM123 ")
	if err != nil {
		t.Fatalf("build requirement: %v", err)
	}

	want := `identifier "com.gethasp.hasp.HASP" and anchor apple generic and certificate leaf[subject.OU] = "TEAM123" and certificate 1[field.1.2.840.113635.100.6.2.6] exists`
	if requirement != want {
		t.Fatalf("requirement = %q, want %q", requirement, want)
	}
}

func TestHASPAppDesignatedRequirementRequiresTeamID(t *testing.T) {
	requirement, err := HASPAppDesignatedRequirement(" \t ")
	if err == nil {
		t.Fatal("expected empty team ID rejection")
	}
	if requirement != "" {
		t.Fatalf("requirement = %q, want empty", requirement)
	}
}

func TestDesignatedRequirementAttestorVerifyPIDRequiresRequirement(t *testing.T) {
	var attestor *DesignatedRequirementAttestor
	if err := attestor.VerifyPID(42); err == nil {
		t.Fatal("expected nil attestor rejection")
	}

	attestor = &DesignatedRequirementAttestor{}
	if err := attestor.VerifyPID(42); err == nil {
		t.Fatal("expected empty requirement rejection")
	}
}

func TestDesignatedRequirementAttestorVerifyPIDRejectsNonPositivePID(t *testing.T) {
	attestor, err := NewDesignatedRequirementAttestor(`identifier "com.gethasp.hasp.HASP"`)
	if err != nil {
		t.Fatalf("new attestor: %v", err)
	}

	orig := verifyPIDRequirement
	t.Cleanup(func() {
		verifyPIDRequirement = orig
	})

	called := false
	verifyPIDRequirement = func(int, string) error {
		called = true
		return nil
	}

	err = attestor.VerifyPID(0)
	if !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("expected rejected error, got %v", err)
	}
	if called {
		t.Fatal("platform verifier should not be called for non-positive PID")
	}
}

func TestDesignatedRequirementAttestorVerifyPIDDelegatesToPlatformVerifier(t *testing.T) {
	attestor, err := NewDesignatedRequirementAttestor(`identifier "com.gethasp.hasp.HASP"`)
	if err != nil {
		t.Fatalf("new attestor: %v", err)
	}

	orig := verifyPIDRequirement
	t.Cleanup(func() {
		verifyPIDRequirement = orig
	})

	var gotPID int
	var gotRequirement string
	verifyPIDRequirement = func(pid int, requirement string) error {
		gotPID = pid
		gotRequirement = requirement
		return nil
	}

	if err := attestor.VerifyPID(1234); err != nil {
		t.Fatalf("verify pid: %v", err)
	}
	if gotPID != 1234 {
		t.Fatalf("pid = %d, want 1234", gotPID)
	}
	if gotRequirement != `identifier "com.gethasp.hasp.HASP"` {
		t.Fatalf("requirement = %q", gotRequirement)
	}
}

func TestDesignatedRequirementAttestorVerifyPIDPropagatesPlatformVerifierError(t *testing.T) {
	attestor, err := NewDesignatedRequirementAttestor(`identifier "com.gethasp.hasp.HASP"`)
	if err != nil {
		t.Fatalf("new attestor: %v", err)
	}

	orig := verifyPIDRequirement
	t.Cleanup(func() {
		verifyPIDRequirement = orig
	})

	verifyPIDRequirement = func(int, string) error {
		return ErrAttestationUnavailable
	}

	err = attestor.VerifyPID(1234)
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func TestPeerPIDContextAndClipboardRevealHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/clipboard", nil)
	pid, err := PeerPIDFromContext(req.WithContext(WithPeerPID(req.Context(), 4242)))
	if err != nil {
		t.Fatalf("peer pid: %v", err)
	}
	if pid != 4242 {
		t.Fatalf("pid = %d", pid)
	}
	if _, err := PeerPIDFromContext(nil); !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("nil request err = %v", err)
	}
	if _, err := PeerPIDFromContext(req); !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("missing pid err = %v", err)
	}
	if !isClipboardRevealRequest(req) || isClipboardRevealRequest(nil) {
		t.Fatal("clipboard reveal helper mismatch")
	}
}

func TestRevealAttestationMiddlewareRejectsMismatchedCaller(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RevealAttestationMiddleware(fakeAttestor{err: ErrAttestationRejected}, func(*http.Request) (int, error) {
		return 42, nil
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/inline", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	if nextCalled {
		t.Fatal("next handler should not run after failed attestation")
	}
}

func TestRevealAttestationMiddlewareAllowsAttestedCaller(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RevealAttestationMiddleware(fakeAttestor{}, func(*http.Request) (int, error) {
		return 42, nil
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/clipboard", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.Code)
	}
}

func TestRevealAttestationResidualBranches(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/items/api/reveal/inline", nil)
	resp := httptest.NewRecorder()
	RevealAttestationMiddlewareWithAudit(nil, nil, nil, nil).ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("non-reveal nil next status = %d", resp.Code)
	}

	var recorded error
	req = httptest.NewRequest(http.MethodPost, "/v1/items/api/reveal/inline", nil)
	resp = httptest.NewRecorder()
	RevealAttestationMiddlewareWithAudit(nil, nil, func(_ *http.Request, err error) {
		recorded = err
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden || !errors.Is(recorded, ErrAttestationUnavailable) {
		t.Fatalf("nil attestation status=%d recorded=%v", resp.Code, recorded)
	}

	for _, path := range []string{
		"/v1/secrets//reveal",
		"/v1/items/folder/name/reveal/clipboard",
	} {
		if _, ok, err := RevealSecretRef(httptest.NewRequest(http.MethodPost, path, nil)); !ok || err == nil {
			t.Fatalf("invalid reveal ref %s ok=%t err=%v", path, ok, err)
		}
	}
	if _, ok, err := RevealSecretRef(httptest.NewRequest(http.MethodPost, "/v1/unknown/api/reveal", nil)); ok || err != nil {
		t.Fatalf("unknown reveal route ok=%t err=%v", ok, err)
	}
	if err := verifyPIDDesignatedRequirement(0, `identifier "com.gethasp.hasp.HASP"`); !errors.Is(err, ErrAttestationRejected) {
		t.Fatalf("non-positive pid err = %v", err)
	}
}

func TestRevealAttestationMiddlewareUsesPeerPIDSourceInsteadOfRequestControlledFields(t *testing.T) {
	var attestedPID int
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RevealAttestationMiddleware(attestorFunc(func(pid int) error {
		attestedPID = pid
		return nil
	}), func(*http.Request) (int, error) {
		return 42, nil
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/inline?pid=999999", bytes.NewBufferString(`{"pid":999999}`))
	req.RemoteAddr = "127.0.0.1:999999"
	req.Header.Set("X-HASP-Peer-PID", "999999")
	req.Header.Set("Content-Type", "application/json")

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.Code)
	}
	if attestedPID != 42 {
		t.Fatalf("attested pid = %d, want peer source pid 42", attestedPID)
	}
}

func TestRevealAttestationMiddlewareRecordsFailure(t *testing.T) {
	nextCalled := false
	var recordedPath string
	var recordedErr error
	handler := RevealAttestationMiddlewareWithAudit(
		fakeAttestor{},
		func(*http.Request) (int, error) {
			return 0, ErrAttestationRejected
		},
		func(r *http.Request, err error) {
			recordedPath = r.URL.EscapedPath()
			recordedErr = err
		},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/items/secret_01/reveal/inline", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	if nextCalled {
		t.Fatal("next handler should not run after failed attestation")
	}
	if recordedPath != "/v1/items/secret_01/reveal/inline" {
		t.Fatalf("recorded path = %q", recordedPath)
	}
	if !errors.Is(recordedErr, ErrAttestationRejected) {
		t.Fatalf("recorded error = %v, want rejected", recordedErr)
	}
}

func TestRevealAttestationMiddlewareDoesNotGateOtherRoutes(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RevealAttestationMiddleware(fakeAttestor{err: ErrAttestationRejected}, nil, next)

	req := httptest.NewRequest(http.MethodGet, "/v1/items/secret_01", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.Code)
	}
}

type fakeAttestor struct {
	err error
}

func (f fakeAttestor) VerifyPID(int) error {
	return f.err
}

type attestorFunc func(pid int) error

func (f attestorFunc) VerifyPID(pid int) error {
	return f(pid)
}
