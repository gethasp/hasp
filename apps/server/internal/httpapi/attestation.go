package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrAttestationUnavailable = errors.New("attestation unavailable")
	ErrAttestationRejected    = errors.New("attestation rejected")
)

const HASPAppBundleID = "com.gethasp.hasp.HASP"

var verifyPIDRequirement = verifyPIDDesignatedRequirement

type peerPIDContextKey struct{}

type Attestor interface {
	VerifyPID(pid int) error
}

type DesignatedRequirementAttestor struct {
	requirement string
}

func NewDesignatedRequirementAttestor(requirement string) (*DesignatedRequirementAttestor, error) {
	requirement = strings.TrimSpace(requirement)
	if requirement == "" {
		return nil, errors.New("httpapi: designated requirement is required")
	}
	return &DesignatedRequirementAttestor{requirement: requirement}, nil
}

func HASPAppDesignatedRequirement(teamID string) (string, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return "", errors.New("httpapi: team id is required")
	}
	return fmt.Sprintf(`identifier "%s" and anchor apple generic and certificate leaf[subject.OU] = "%s" and certificate 1[field.1.2.840.113635.100.6.2.6] exists`, HASPAppBundleID, teamID), nil
}

func (a *DesignatedRequirementAttestor) VerifyPID(pid int) error {
	if a == nil || strings.TrimSpace(a.requirement) == "" {
		return errors.New("httpapi: designated requirement is required")
	}
	if pid <= 0 {
		return fmt.Errorf("%w: pid must be positive", ErrAttestationRejected)
	}
	if err := verifyPIDRequirement(pid, a.requirement); err != nil {
		return err
	}
	return nil
}

type PeerPIDSource func(*http.Request) (int, error)
type AttestationFailureRecorder func(*http.Request, error)

func WithPeerPID(ctx context.Context, pid int) context.Context {
	return context.WithValue(ctx, peerPIDContextKey{}, pid)
}

func PeerPIDFromContext(r *http.Request) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("%w: request is required", ErrAttestationRejected)
	}
	pid, ok := r.Context().Value(peerPIDContextKey{}).(int)
	if !ok || pid <= 0 {
		return 0, fmt.Errorf("%w: trusted peer pid is unavailable", ErrAttestationRejected)
	}
	return pid, nil
}

func RevealAttestationMiddleware(attestor Attestor, source PeerPIDSource, next http.Handler) http.Handler {
	return RevealAttestationMiddlewareWithAudit(attestor, source, nil, next)
}

func RevealAttestationMiddlewareWithAudit(attestor Attestor, source PeerPIDSource, recorder AttestationFailureRecorder, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsRevealRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if attestor == nil || source == nil {
			recordAttestationFailure(recorder, r, ErrAttestationUnavailable)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		pid, err := source(r)
		if err != nil {
			recordAttestationFailure(recorder, r, err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if err := attestor.VerifyPID(pid); err != nil {
			if errors.Is(err, ErrAttestationUnavailable) && isClipboardRevealRequest(r) && allowClipboardRevealWithoutAttestation() {
				next.ServeHTTP(w, r)
				return
			}
			recordAttestationFailure(recorder, r, err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func recordAttestationFailure(recorder AttestationFailureRecorder, r *http.Request, err error) {
	if recorder != nil {
		recorder(r, err)
	}
}

func IsRevealRequest(r *http.Request) bool {
	_, ok, _ := RevealSecretRef(r)
	return ok
}

func RevealSecretRef(r *http.Request) (string, bool, error) {
	if r == nil || r.Method != http.MethodPost || r.URL == nil {
		return "", false, nil
	}
	path := r.URL.EscapedPath()
	var ref string
	switch {
	case strings.HasPrefix(path, "/v1/secrets/") && strings.HasSuffix(path, "/reveal"):
		ref = strings.TrimSuffix(strings.TrimPrefix(path, "/v1/secrets/"), "/reveal")
	case strings.HasPrefix(path, "/v1/items/") && strings.HasSuffix(path, "/reveal/inline"):
		ref = strings.TrimSuffix(strings.TrimPrefix(path, "/v1/items/"), "/reveal/inline")
	case strings.HasPrefix(path, "/v1/items/") && strings.HasSuffix(path, "/reveal/clipboard"):
		ref = strings.TrimSuffix(strings.TrimPrefix(path, "/v1/items/"), "/reveal/clipboard")
	default:
		return "", false, nil
	}
	decoded, _ := url.PathUnescape(ref)
	decoded = strings.TrimSpace(decoded)
	if decoded == "" || strings.Contains(decoded, "/") {
		return "", true, errors.New("secret id is required")
	}
	return decoded, true, nil
}

func isClipboardRevealRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	return strings.HasSuffix(r.URL.EscapedPath(), "/reveal/clipboard")
}
