package runtime

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/accessmatrix"
	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/app/auditops"
	"github.com/gethasp/hasp/apps/server/internal/app/dashboard"
	revealcore "github.com/gethasp/hasp/apps/server/internal/app/reveal"
	"github.com/gethasp/hasp/apps/server/internal/approvals"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/integrations"
	"github.com/gethasp/hasp/apps/server/internal/jsonwire"
	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type Manager struct {
	paths paths.Paths
}

var spawnDaemonProcess = startDetachedProcess

// daemonStartupTimeout caps how long EnsureDaemon waits for a freshly-spawned
// daemon to bind its socket and pass verifyDaemon. The previous 5-second
// budget was tight on cold launchd start with a Keychain unlock prompt
// (the user has to physically click "Allow"), and on first run after a
// reboot when argon2id KDF parameters are sized aggressively. 15s gives
// the daemon room for both without silently turning a slow start into a
// hard failure that requires a retry.
const daemonStartupTimeout = 15 * time.Second

var (
	resolveRuntimePaths  = paths.Resolve
	registerServerName   = func(server *rpc.Server, name string, rcvr any) error { return server.RegisterName(name, rcvr) }
	runtimeMkdirAll      = os.MkdirAll
	runtimeRemove        = os.Remove
	listenUnix           = net.Listen
	writeFile            = os.WriteFile
	chmodFile            = os.Chmod
	newRuntimeAuditLog   = audit.New
	httpHMACKey          = defaultHTTPHMACKey
	httpAttestor         = newHASPAppAttestor
	restartDaemonProcess = func() {
		os.Exit(75)
	}
)

var errVaultLocked = errors.New("vault is locked")

const (
	headerRequestID       = "HASP-Request-Id"
	revealIdempotencyTTL  = 60 * time.Second
	revealRateLimitWindow = 10 * time.Second
	revealRateLimitCount  = 10
	revealResponseTTL     = 60
	backupSchedulerTick   = time.Minute
	backupPassphraseSvc   = "com.gethasp.hasp.backup.passphrase"
)

type revealCacheEntry struct {
	expiresAt time.Time
	actor     string
	secretRef string
	status    int
	body      []byte
}

type revealInflight struct {
	actor     string
	secretRef string
	done      chan struct{}
	entry     revealCacheEntry
	err       error
}

type revealResponse struct {
	Schema      int    `json:"_schema"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Value       string `json:"value"`
	Algorithm   string `json:"algorithm"`
	Nonce       string `json:"nonce"`
	RetrievedAt string `json:"retrieved_at"`
	TTLS        int    `json:"ttl_s"`
	RequestID   string `json:"request_id"`
}

func NewManager() (*Manager, error) {
	resolved, err := resolveRuntimePaths()
	if err != nil {
		return nil, err
	}
	return &Manager{paths: resolved}, nil
}

func (m *Manager) SocketPath() string {
	return m.paths.SocketPath
}

func (m *Manager) EnsureDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := runtimeMkdirAll(m.paths.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	if client, err := Dial(ctx, m.paths.SocketPath); err == nil {
		ok := verifyDaemon(ctx, client, m.paths.SocketPath)
		_ = client.Close()
		if ok {
			return nil
		}
	}
	if err := runtimeRemove(m.paths.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove untrusted socket: %w", err)
	}
	for _, sidecar := range httpSidecarPaths(m.paths) {
		if err := runtimeRemove(sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove untrusted socket sidecar: %w", err)
		}
	}
	if err := spawnDaemonProcess(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(daemonStartupTimeout)
	for time.Now().Before(deadline) {
		client, err := Dial(ctx, m.paths.SocketPath)
		if err == nil {
			ok := verifyDaemon(ctx, client, m.paths.SocketPath)
			_ = client.Close()
			if ok {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("timed out waiting for hasp daemon")
}

func verifyDaemon(ctx context.Context, client *Client, socketPath string) bool {
	ping, err := client.Ping(ctx)
	if err != nil || ping.Name != "hasp" {
		return false
	}
	status, err := client.Status(ctx)
	if err != nil {
		return false
	}
	return status.SocketPath == socketPath && status.PID > 0
}

func (m *Manager) StartDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return spawnDaemonProcess(ctx)
}

func (m *Manager) StopDaemon() error {
	return stopDetachedProcess()
}

func (m *Manager) RunDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := runtimeMkdirAll(m.paths.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	if err := removeStaleSocket(m.paths.SocketPath); err != nil {
		return err
	}
	listener, err := listenUnix("unix", m.paths.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = runtimeRemove(m.paths.SocketPath)
	}()
	if err := chmodFile(m.paths.SocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	if err := writeFile(m.paths.PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer func() {
		_ = runtimeRemove(m.paths.PidFilePath)
	}()

	server := newRPCServer(m.paths)
	if err := server.register(); err != nil {
		return err
	}
	errCh := make(chan error, 2)
	httpServer, err := startHTTPServer(ctx, m.paths, server, errCh)
	if err != nil {
		return err
	}
	defer func() {
		_ = httpServer.Close()
	}()

	go func() {
		errCh <- server.serve(ctx, listener)
	}()

	select {
	case <-ctx.Done():
		server.stop()
		return nil
	case err := <-errCh:
		return err
	}
}

func startHTTPServer(ctx context.Context, runtimePaths paths.Paths, rpcSrv *rpcServer, errCh chan<- error) (*httpapi.Server, error) {
	key, err := httpHMACKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("HMAC secret not provisioned: %w", err)
	}
	validator, err := httpapi.NewValidator(key, httpapi.ValidatorOptions{})
	if err != nil {
		return nil, err
	}
	rpcSrv.setHTTPHMACKey(key)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET or HEAD is required")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
		}
	})
	mux.HandleFunc("/v1/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		payload, err := rpcSrv.dashboardSnapshot()
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusServiceUnavailable, "vault_state_unavailable", "Vault state unavailable", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, payload)
	})
	mux.HandleFunc("/v1/dashboard/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		payload, err := rpcSrv.dashboardSnapshot()
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusServiceUnavailable, "vault_state_unavailable", "Vault state unavailable", err.Error())
			return
		}
		var out any
		switch strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/dashboard/"), "/") {
		case "vault":
			out = payload.Vault
		case "leases":
			out = payload.Leases
		case "approvals":
			out = payload.Approvals
		case "audit":
			out = payload.Audit
		case "integrations":
			out = payload.Integrations
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, out)
	})
	mux.HandleFunc("/v1/leases", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		req, err := listLeasesRequestFromHTTP(r)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		broker := rpcSrv.broker()
		var reply ListLeasesResponse
		if err := broker.ListLeases(req, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "lease_list_failed", "Lease list failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/leases/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		leaseID, ok := leaseRevokeIDFromPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var req RevokeLeaseRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		req.LeaseID = leaseID
		broker := rpcSrv.broker()
		var reply RevokeLeaseResponse
		if err := broker.RevokeLease(req, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "lease_revoke_failed", "Lease revoke failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/leases/bulk-revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		var req RevokeLeaseRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		if req.AllForConsumer == "" {
			req.AllForConsumer = strings.TrimSpace(r.URL.Query().Get("consumer"))
		}
		if req.AllForConsumer == "" {
			req.AllForConsumer = strings.TrimSpace(r.URL.Query().Get("consumer_id"))
		}
		broker := rpcSrv.broker()
		var reply RevokeLeaseResponse
		if err := broker.RevokeLease(req, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "lease_revoke_failed", "Lease revoke failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		req := ListApprovalsRequest{
			Status:     strings.TrimSpace(r.URL.Query().Get("status")),
			ConsumerID: strings.TrimSpace(r.URL.Query().Get("consumer")),
		}
		if req.ConsumerID == "" {
			req.ConsumerID = strings.TrimSpace(r.URL.Query().Get("consumer_id"))
		}
		broker := rpcSrv.broker()
		var reply ListApprovalsResponse
		if err := broker.ListApprovals(req, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "approval_list_failed", "Approval list failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/approvals/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			approvalID, ok := approvalDetailIDFromPath(r.URL.Path)
			if !ok {
				http.NotFound(w, r)
				return
			}
			reply, err := rpcSrv.approvalDetailSnapshot(approvalID)
			if err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "approval_detail_failed", "Approval detail failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
			return
		}
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET or POST is required")
			return
		}
		approvalID, ok := approvalDecideIDFromPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var req DecideApprovalRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		req.ApprovalID = approvalID
		values := r.URL.Query()
		if req.Decision == "" {
			req.Decision = strings.TrimSpace(values.Get("decision"))
		}
		if req.Scope == "" {
			req.Scope = strings.TrimSpace(values.Get("scope"))
		}
		if req.Reason == "" {
			req.Reason = strings.TrimSpace(values.Get("reason"))
		}
		if req.AuthMethod == "" {
			req.AuthMethod = strings.TrimSpace(values.Get("auth_method"))
		}
		if req.GrantedTTLS == 0 {
			if raw := strings.TrimSpace(values.Get("granted_ttl_s")); raw != "" {
				ttl, err := strconv.Atoi(raw)
				if err != nil || ttl < 0 {
					httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", fmt.Sprintf("invalid granted_ttl_s %q", raw))
					return
				}
				req.GrantedTTLS = ttl
			}
		}
		if req.HoldDurationMS == 0 {
			if raw := strings.TrimSpace(values.Get("hold_duration_ms")); raw != "" {
				holdDuration, err := strconv.Atoi(raw)
				if err != nil || holdDuration < 0 {
					httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", fmt.Sprintf("invalid hold_duration_ms %q", raw))
					return
				}
				req.HoldDurationMS = holdDuration
			}
		}
		req.Actor = "http"
		broker := rpcSrv.broker()
		var reply DecideApprovalResponse
		if err := broker.DecideApproval(req, &reply); err != nil {
			if errors.Is(err, errVaultLocked) {
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "approval_decide_failed", "Approval decide failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/access/matrix", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		req, err := accessMatrixRequestFromHTTP(r)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		broker := rpcSrv.broker()
		var reply AccessMatrixResponse
		if err := broker.AccessMatrix(req, &reply); err != nil {
			if errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized) {
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "access_matrix_failed", "Access matrix failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/integrations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		var reply IntegrationListResponse
		if err := rpcSrv.broker().Integrations(IntegrationGetRequest{}, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "integration_list_failed", "Integration list failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/integrations/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == "/v1/integrations/profiles" {
			switch r.Method {
			case http.MethodGet:
				var reply IntegrationProfilesResponse
				if err := rpcSrv.broker().IntegrationProfileCatalog(IntegrationGetRequest{}, &reply); err != nil {
					httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "integration_profiles_failed", "Integration profiles failed", err.Error())
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = jsonwire.WriteResponse(w, reply)
			case http.MethodPost:
				var body IntegrationProfileMutationRequest
				if !decodeJSONObject(w, r, &body, "profile body must contain exactly one JSON object") {
					return
				}
				var reply IntegrationProfileMutationResponse
				err := rpcSrv.broker().CreateIntegrationProfile(IntegrationProfileMutationRPCRequest{Body: body}, &reply)
				if writeIntegrationProfileMutationError(w, err) {
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = jsonwire.WriteResponse(w, reply)
			default:
				httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET or POST is required")
			}
			return
		}
		if targetID, profileID, ok := integrationProfilePath(r.URL.EscapedPath()); ok {
			var body IntegrationProfileMutationRequest
			var reply IntegrationProfileMutationResponse
			switch r.Method {
			case http.MethodPut:
				if !decodeJSONObject(w, r, &body, "profile body must contain exactly one JSON object") {
					return
				}
				err := rpcSrv.broker().UpdateIntegrationProfile(IntegrationProfileMutationRPCRequest{TargetID: targetID, ProfileID: profileID, IfMatch: r.Header.Get("If-Match"), Body: body}, &reply)
				if writeIntegrationProfileMutationError(w, err) {
					return
				}
			case http.MethodDelete:
				err := rpcSrv.broker().DeleteIntegrationProfile(IntegrationProfileMutationRPCRequest{TargetID: targetID, ProfileID: profileID, IfMatch: r.Header.Get("If-Match")}, &reply)
				if writeIntegrationProfileMutationError(w, err) {
					return
				}
			default:
				httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "PUT or DELETE is required")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
			return
		}
		targetID, action, ok := integrationActionFromPath(r.URL.EscapedPath())
		if !ok {
			httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "integration_not_found", "Integration not found", r.URL.Path)
			return
		}
		broker := rpcSrv.broker()
		switch {
		case r.Method == http.MethodGet && action == "profiles":
			var reply IntegrationProfilesResponse
			err := broker.IntegrationProfiles(IntegrationProfilesRequest{TargetID: targetID}, &reply)
			if err == nil {
				w.Header().Set("Content-Type", "application/json")
				_ = jsonwire.WriteResponse(w, reply)
				return
			}
			if errors.Is(err, integrations.ErrTargetNotFound) {
				httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "integration_not_found", "Integration not found", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "integration_profiles_failed", "Integration profiles failed", err.Error())
		case r.Method == http.MethodPost && action == "doctor":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			defer r.Body.Close()
			var body IntegrationDoctorRequest
			if r.Body != nil {
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
					httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
					return
				}
				if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
					httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "doctor body must contain exactly one JSON object")
					return
				}
			}
			var reply IntegrationDoctorResponse
			err := broker.DoctorIntegration(IntegrationDoctorRPCRequest{TargetID: targetID, ProfileID: body.ProfileID}, &reply)
			if err == nil {
				w.Header().Set("Content-Type", "application/json")
				_ = jsonwire.WriteResponse(w, reply)
				return
			}
			if errors.Is(err, integrations.ErrTargetNotFound) || errors.Is(err, integrations.ErrProfileNotFound) {
				httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "integration_not_found", "Integration not found", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "integration_doctor_failed", "Integration doctor failed", err.Error())
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET profiles or POST doctor is required")
		}
	})
	mux.HandleFunc("/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		broker := rpcSrv.broker()
		switch r.Method {
		case http.MethodGet:
			var reply PolicyResponse
			if err := broker.Policy(PolicyGetRequest{}, &reply); err != nil {
				if errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized) {
					httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
					return
				}
				httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "policy_get_failed", "Policy get failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", reply.Version)
			_ = jsonwire.WriteResponse(w, reply)
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			defer r.Body.Close()
			var policy PolicyDocument
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&policy); err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
			if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "policy body must contain exactly one JSON object")
				return
			}
			var reply PolicyResponse
			err := broker.SetPolicy(PolicySetRequest{
				Policy:    policy,
				IfMatch:   strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`),
				UpdatedBy: "http",
			}, &reply)
			switch {
			case err == nil:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", reply.Version)
				_ = jsonwire.WriteResponse(w, reply)
			case errors.Is(err, store.ErrPolicyVersionConflict):
				httpapi.WriteErrorEnvelope(w, http.StatusConflict, "policy_version_conflict", "Policy version conflict", err.Error())
			case errors.Is(err, store.ErrPolicyInvalid):
				httpapi.WriteErrorEnvelope(w, http.StatusUnprocessableEntity, "policy_invalid", "Policy invalid", err.Error())
			case errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized):
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
			default:
				httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "policy_set_failed", "Policy set failed", err.Error())
			}
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET or PUT is required")
		}
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		var reply ConfigResponse
		if err := rpcSrv.broker().Config(ConfigGetRequest{}, &reply); err != nil {
			if errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized) {
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "config_get_failed", "Config get failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/config/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "PUT is required")
			return
		}
		keyPath := strings.TrimPrefix(r.URL.Path, "/v1/config/")
		key, err := url.PathUnescape(keyPath)
		if err != nil || keyPath == "" || strings.Contains(keyPath, "/") || strings.Contains(key, "/") || strings.TrimSpace(key) != key {
			httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "config_key_not_found", "Config key not found", keyPath)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer r.Body.Close()
		var body ConfigValue
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "config body must contain exactly one JSON object")
			return
		}
		var reply ConfigValueResponse
		err = rpcSrv.broker().SetConfig(ConfigSetRequest{Key: key, Value: body.Value, Actor: "http"}, &reply)
		switch {
		case err == nil:
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
		case errors.Is(err, store.ErrConfigKeyNotFound):
			httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "config_key_not_found", "Config key not found", err.Error())
		case errors.Is(err, store.ErrConfigInvalid):
			httpapi.WriteErrorEnvelope(w, http.StatusUnprocessableEntity, "config_invalid", "Config invalid", err.Error())
		case errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized):
			httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "config_set_failed", "Config set failed", err.Error())
		}
	})
	mux.HandleFunc("/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		reply, err := rpcSrv.secretsListSnapshot(r.Context())
		if err != nil {
			if errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, store.ErrInvalidPassword) || errors.Is(err, store.ErrVaultNotInitialized) {
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "secrets_list_failed", "Secrets list failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET or POST is required")
			return
		}
		reply, err := rpcSrv.auditVerifySnapshot(true)
		if err != nil {
			if rpcSrv.events != nil {
				rpcSrv.events.publish("audit.changed", `{"action":"audit.verify","status":"failed"}`)
				rpcSrv.events.publish("dashboard.changed", `{"source":"audit.verify","status":"failed"}`)
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "audit_verify_failed", "Audit verify failed", err.Error())
			return
		}
		if rpcSrv.events != nil {
			status := "ok"
			if !reply.ChainOK {
				status = "failed"
			}
			rpcSrv.events.publish("audit.changed", fmt.Sprintf(`{"action":"audit.verify","status":%q}`, status))
			rpcSrv.events.publish("dashboard.changed", fmt.Sprintf(`{"source":"audit.verify","status":%q}`, status))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		opts, err := auditExportOptionsFromHTTP(r)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		if err := rpcSrv.auditExportNDJSON(w, opts); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "audit_export_failed", "Audit export failed", err.Error())
			return
		}
	})
	mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		limit, err := auditLimitFromHTTP(r)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		reply, err := rpcSrv.auditListSnapshot(limit)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "audit_list_failed", "Audit list failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	backupHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer r.Body.Close()
		var req BackupRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "backup body must contain exactly one JSON object")
			return
		}
		var reply BackupResponse
		err := rpcSrv.broker().Backup(req, &reply)
		switch {
		case err == nil:
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
		case errors.Is(err, store.ErrKeyringUnavailable), errors.Is(err, store.ErrInvalidPassword), errors.Is(err, store.ErrVaultNotInitialized):
			httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "backup_failed", "Backup failed", err.Error())
		}
	}
	mux.HandleFunc("/v1/backup", backupHandler)
	mux.HandleFunc("/v1/backups/export", backupHandler)
	mux.HandleFunc("/v1/backups/passphrase", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			reply := rpcSrv.broker().BackupPassphraseStatus()
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
			defer r.Body.Close()
			var req BackupPassphraseRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&req); err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
			if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "backup passphrase body must contain exactly one JSON object")
				return
			}
			reply, err := rpcSrv.broker().SetBackupPassphrase(req)
			if err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "backup_passphrase_failed", "Backup passphrase custody failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
		case http.MethodDelete:
			reply, err := rpcSrv.broker().DeleteBackupPassphrase()
			if err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "backup_passphrase_failed", "Backup passphrase custody failed", err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = jsonwire.WriteResponse(w, reply)
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET, PUT, or DELETE is required")
		}
	})
	mux.HandleFunc("/v1/vault/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, rpcSrv.vaultStatusSnapshot())
	})
	mux.HandleFunc("/v1/vault/init", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		var req InitVaultRequest
		if r.Body != nil {
			defer r.Body.Close()
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&req); err != nil {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "unexpected trailing JSON")
				return
			}
		}
		if len(req.MasterPassword) < 12 {
			httpapi.WriteErrorEnvelope(w, http.StatusUnprocessableEntity, "invalid_master_password", "Invalid master password", "master password must be at least 12 characters")
			return
		}
		vaultStore, err := store.NewForPaths(rpcSrv.keyring, rpcSrv.paths)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_init_failed", "Vault initialization failed", err.Error())
			return
		}
		if err := vaultStore.Init(r.Context(), req.MasterPassword); err != nil {
			if errors.Is(err, store.ErrVaultExists) {
				httpapi.WriteErrorEnvelope(w, http.StatusConflict, "vault_exists", "Vault already exists", "unlock the existing vault instead")
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_init_failed", "Vault initialization failed", err.Error())
			return
		}
		handle, err := vaultStore.OpenWithPassword(r.Context(), req.MasterPassword)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_init_failed", "Vault initialization failed", err.Error())
			return
		}
		if err := handle.EnableConvenienceUnlock(r.Context()); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_init_failed", "Vault initialization failed", err.Error())
			return
		}
		broker := rpcSrv.broker()
		var session OpenSessionResponse
		if err := broker.OpenSession(OpenSessionRequest{
			HostLabel:    "HASP.app",
			TTLSeconds:   int(DefaultSessionTTL.Seconds()),
			ConsumerName: "HASP.app",
			Internal:     true,
		}, &session); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_unlock_failed", "Vault unlock failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, InitVaultResponse{Schema: jsonwire.SchemaVersion, Initialized: true, Unlocked: true, RemainingTTL: session.ExpiresAt.Sub(time.Now().UTC()).Seconds()})
	})
	mux.HandleFunc("/v1/vault/unlock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		var req UnlockVaultRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		if strings.TrimSpace(req.Method) != "device-owner" {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "unlock method must be device-owner")
			return
		}
		validateUnlock := rpcSrv.validateVaultUnlock
		if validateUnlock == nil {
			validateUnlock = defaultValidateVaultUnlock
		}
		if err := validateUnlock(r.Context(), rpcSrv.paths); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
			return
		}
		broker := rpcSrv.broker()
		var session OpenSessionResponse
		if err := broker.OpenSession(OpenSessionRequest{
			HostLabel:    "HASP.app",
			TTLSeconds:   int(DefaultSessionTTL.Seconds()),
			ConsumerName: "HASP.app",
			Internal:     true,
		}, &session); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "unlock_failed", "Unlock failed", err.Error())
			return
		}
		broker.appendAudit(audit.EventApprove, "daemon", map[string]any{
			"action":      "vault.unlock",
			"auth_method": strings.TrimSpace(req.Method),
			"internal":    true,
		})
		remainingTTL := time.Until(session.ExpiresAt).Seconds()
		if remainingTTL < 0 {
			remainingTTL = 0
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, UnlockVaultResponse{
			Unlocked:     true,
			RemainingTTL: remainingTTL,
		})
	})
	mux.HandleFunc("/v1/vault/master-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		defer r.Body.Close()
		var req RotateMasterPasswordRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "password body must contain exactly one JSON object")
			return
		}
		callerKey := rpcSrv.masterPasswordCallerKey(r)
		details := rpcSrv.masterPasswordAuditDetails(r)
		if retryAfter := rpcSrv.masterPasswordRetryAfter(callerKey, time.Now().UTC()); retryAfter > 0 {
			details["result"] = "rate_limited"
			details["retry_after_seconds"] = int(math.Ceil(retryAfter.Seconds()))
			rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
			httpapi.WriteErrorEnvelope(w, http.StatusTooManyRequests, "master_password_rate_limited", "Too many attempts", "too many failed master password change attempts; wait before retrying")
			return
		}
		vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), rpcSrv.paths)
		if err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_rekey_failed", "Vault rekey failed", err.Error())
			return
		}
		handle, err := vaultStore.OpenWithPassword(r.Context(), req.CurrentPassword)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrInvalidPassword):
				rpcSrv.recordMasterPasswordFailure(callerKey, time.Now().UTC())
				details["result"] = "invalid_current_password"
				rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
				httpapi.WriteErrorEnvelope(w, http.StatusForbidden, "invalid_master_password", "Invalid master password", "current master password is incorrect")
			case errors.Is(err, store.ErrVaultNotInitialized):
				details["result"] = "vault_not_initialized"
				rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
				httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", err.Error())
			default:
				details["result"] = "open_failed"
				details["error"] = err.Error()
				rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
				httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_rekey_failed", "Vault rekey failed", err.Error())
			}
			return
		}
		if err := handle.RekeyPassword(r.Context(), req.CurrentPassword, req.NewPassword); err != nil {
			switch {
			case errors.Is(err, store.ErrInvalidPassword):
				rpcSrv.recordMasterPasswordFailure(callerKey, time.Now().UTC())
				details["result"] = "invalid_current_password"
				rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
				httpapi.WriteErrorEnvelope(w, http.StatusForbidden, "invalid_master_password", "Invalid master password", "current master password is incorrect")
			default:
				details["result"] = "invalid_new_password"
				details["error"] = err.Error()
				rpcSrv.appendMasterPasswordAudit(audit.EventDeny, details)
				httpapi.WriteErrorEnvelope(w, http.StatusUnprocessableEntity, "invalid_new_master_password", "Invalid new master password", err.Error())
			}
			return
		}
		rpcSrv.clearMasterPasswordFailures(callerKey)
		details["result"] = "rotated"
		rpcSrv.appendMasterPasswordAudit(audit.EventApprove, details)
		var lockReply LockVaultResponse
		if err := rpcSrv.broker().LockVault(LockVaultRequest{Cause: "master-password-change"}, &lockReply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "vault_lock_failed", "Vault lock failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, RotateMasterPasswordResponse{
			Schema:       jsonwire.SchemaVersion,
			Rotated:      true,
			RevokedCount: lockReply.RevokedCount,
		})
	})
	mux.HandleFunc("/v1/vault/lock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		var req LockVaultRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		broker := rpcSrv.broker()
		var reply LockVaultResponse
		if err := broker.LockVault(req, &reply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "lock_failed", "Lock failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, reply)
	})
	mux.HandleFunc("/v1/daemon/http-key/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
			return
		}
		key := rpcSrv.httpRevealKey()
		if len(key) == 0 {
			details := rpcSrv.httpAuditDetails(r, httpKeyFingerprintAction)
			details["result"] = "missing_key"
			rpcSrv.appendDaemonSecurityAudit(audit.EventDeny, details)
			httpapi.WriteErrorEnvelope(w, http.StatusServiceUnavailable, "hmac_key_unavailable", "HMAC key unavailable", "daemon HTTP HMAC key is not available")
			return
		}
		details := rpcSrv.httpAuditDetails(r, httpKeyFingerprintAction)
		details["result"] = "revealed"
		rpcSrv.appendDaemonSecurityAudit(audit.EventApprove, details)
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, HTTPKeyFingerprintResponse{
			Schema:      jsonwire.SchemaVersion,
			Fingerprint: strings.ToUpper(httpapi.HMACKeyFingerprintForKey(key)),
		})
	})
	mux.HandleFunc("/v1/daemon/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "POST is required")
			return
		}
		var req RestartDaemonRequest
		if r.Body != nil {
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
				return
			}
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "operator"
		}
		broker := rpcSrv.broker()
		var lockReply LockVaultResponse
		if err := broker.LockVault(LockVaultRequest{Cause: "daemon-restart"}, &lockReply); err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "restart_failed", "Restart failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = jsonwire.WriteResponse(w, RestartDaemonResponse{Accepted: true, Reason: reason})
		go func() {
			time.Sleep(100 * time.Millisecond)
			restartDaemonProcess()
		}()
	})
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		rpcSrv.handleHTTPEvents(w, r)
	})
	mux.HandleFunc("/v1/items/", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.IsRevealRequest(r) {
			http.NotFound(w, r)
			return
		}
		rpcSrv.handleHTTPReveal(w, r)
	})
	mux.HandleFunc("/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if !httpapi.IsRevealRequest(r) {
			http.NotFound(w, r)
			return
		}
		rpcSrv.handleHTTPReveal(w, r)
	})
	go rpcSrv.broker().runScheduledBackups(ctx)
	attestor, err := httpAttestor()
	if err != nil {
		return nil, err
	}
	handler := httpapi.RevealAttestationMiddlewareWithAudit(attestor, httpapi.PeerPIDFromContext, rpcSrv.recordAttestationFailure, mux)
	handler = hmacValidatorMiddleware(validator, rpcSrv.recordAttestationFailure, handler)
	normalizedPaths := normalizeHTTPPaths(runtimePaths)
	httpServer, err := httpapi.NewServer(normalizedPaths, httpapi.Options{
		Handler:        handler,
		UnixSocketPath: normalizedPaths.HTTPUnixSocketPath,
		PeerPID:        rpcSrv.peerPID,
		StartedAt:      rpcSrv.startedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("start http api: %w", err)
	}
	rpcSrv.setHTTPListener(httpServer.Ports())
	go func() {
		if err := httpServer.Serve(ctx); err != nil {
			select {
			case errCh <- fmt.Errorf("serve http api: %w", err):
			case <-ctx.Done():
			}
		}
	}()
	return httpServer, nil
}

func (s *rpcServer) setHTTPListener(ports httpapi.PortFileState) {
	host := "127.0.0.1"
	port := ports.V4
	if port == 0 && ports.V6 != 0 {
		host = "::1"
		port = ports.V6
	}
	s.httpMu.Lock()
	s.httpListener = dashboard.HTTPListener{Host: host, Port: port}
	s.httpMu.Unlock()
}

func (s *rpcServer) setHTTPHMACKey(key []byte) {
	s.httpMu.Lock()
	s.httpHMACKey = append([]byte(nil), key...)
	s.httpMu.Unlock()
}

func (s *rpcServer) httpRevealKey() []byte {
	s.httpMu.RLock()
	defer s.httpMu.RUnlock()
	return append([]byte(nil), s.httpHMACKey...)
}

func (s *rpcServer) handleHTTPReveal(w http.ResponseWriter, r *http.Request) {
	secretRef, err := revealSecretRef(r)
	if err != nil {
		httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "not_found", "Not found", err.Error())
		return
	}
	requestID := strings.TrimSpace(r.Header.Get(headerRequestID))
	if !isUUIDV7(requestID) {
		httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", "HASP-Request-Id must be a UUIDv7 value")
		return
	}
	actor := revealActor(r)
	if entry, ok, err := s.revealCacheGet(requestID, actor, secretRef); err != nil {
		httpapi.WriteErrorEnvelope(w, http.StatusConflict, "request_id_conflict", "Request ID conflict", err.Error())
		return
	} else if ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(entry.status)
		_, _ = w.Write(entry.body)
		return
	}
	if s.sessions == nil || s.sessions.IsLocked() {
		httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", "unlock the vault before revealing secrets")
		return
	}
	inflight, owner, err := s.revealBegin(requestID, actor, secretRef)
	if err != nil {
		httpapi.WriteErrorEnvelope(w, http.StatusConflict, "request_id_conflict", "Request ID conflict", err.Error())
		return
	}
	if !owner {
		<-inflight.done
		if inflight.err != nil {
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "reveal_failed", "Reveal failed", inflight.err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(inflight.entry.status)
		_, _ = w.Write(inflight.entry.body)
		return
	}
	var finishEntry revealCacheEntry
	var finishErr error
	defer func() {
		s.revealFinish(requestID, finishEntry, finishErr)
	}()
	if !s.allowReveal(actor, time.Now().UTC()) {
		finishErr = errors.New("too many reveal requests")
		httpapi.WriteErrorEnvelope(w, http.StatusTooManyRequests, "rate_limited", "Rate limited", "too many reveal requests")
		return
	}
	getItem := s.revealItem
	if getItem == nil {
		getItem = defaultRevealItem
	}
	item, err := revealcore.Run(r.Context(), revealcore.Request{Ref: secretRef}, revealcore.Deps{
		Find: func(ctx context.Context, ref string) (revealcore.Payload, error) {
			return getItem(ctx, s.paths, ref)
		},
	})
	if err != nil {
		finishErr = err
		switch {
		case errors.Is(err, store.ErrItemNotFound):
			httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "not_found", "Not found", "secret not found")
		case errors.Is(err, store.ErrKeyringUnavailable), errors.Is(err, store.ErrInvalidPassword), errors.Is(err, store.ErrVaultNotInitialized):
			httpapi.WriteErrorEnvelope(w, http.StatusLocked, "vault_locked", "Vault locked", "vault contents are not available to the daemon")
		default:
			httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "reveal_failed", "Reveal failed", err.Error())
		}
		return
	}
	key := s.httpRevealKey()
	if len(key) == 0 {
		finishErr = errors.New("HTTP reveal key is unavailable")
		httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "reveal_failed", "Reveal failed", "HTTP reveal key is unavailable")
		return
	}
	payload, err := s.buildRevealResponse(key, item, requestID)
	if err != nil {
		finishErr = err
		httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "reveal_failed", "Reveal failed", err.Error())
		return
	}
	if err := s.appendRevealAudit(actor, item, requestID); err != nil {
		finishErr = err
		httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "audit_failed", "Audit failed", err.Error())
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		finishErr = err
		httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "reveal_failed", "Reveal failed", err.Error())
		return
	}
	body = append(body, '\n')
	finishEntry = revealCacheEntry{
		expiresAt: time.Now().UTC().Add(revealIdempotencyTTL),
		actor:     actor,
		secretRef: secretRef,
		status:    http.StatusOK,
		body:      append([]byte(nil), body...),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *rpcServer) buildRevealResponse(key []byte, item revealcore.Payload, requestID string) (revealResponse, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return revealResponse{}, fmt.Errorf("generate reveal nonce: %w", err)
	}
	derived := deriveRevealKey(key, item.ID, requestID)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return revealResponse{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return revealResponse{}, err
	}
	additionalData := []byte(item.ID + "\x00" + requestID)
	ciphertext := gcm.Seal(nil, nonce, item.Value, additionalData)
	return revealResponse{
		Schema:      jsonwire.SchemaVersion,
		ID:          item.ID,
		Name:        item.Name,
		Version:     item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Value:       base64.StdEncoding.EncodeToString(ciphertext),
		Algorithm:   "aes-256-gcm+hasp-hmac-session-v1",
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		RetrievedAt: time.Now().UTC().Format(time.RFC3339Nano),
		TTLS:        revealResponseTTL,
		RequestID:   requestID,
	}, nil
}

func deriveRevealKey(key []byte, itemID string, requestID string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("hasp-reveal-session-v1"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(itemID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(requestID))
	return mac.Sum(nil)
}

func (s *rpcServer) appendRevealAudit(actor string, item revealcore.Payload, requestID string) error {
	if s.audit == nil {
		err := errors.New("audit logger unavailable")
		s.auditState.RecordAppendResult(err)
		return err
	}
	_, err := s.audit.Append("read", actor, map[string]any{
		"action":     "secret.reveal",
		"surface":    "http",
		"item_id":    item.ID,
		"item_name":  item.Name,
		"request_id": requestID,
		"outcome":    "encrypted",
	})
	s.auditState.RecordAppendResult(err)
	return err
}

func (s *rpcServer) revealCacheGet(requestID string, actor string, secretRef string) (revealCacheEntry, bool, error) {
	now := time.Now().UTC()
	s.revealMu.Lock()
	defer s.revealMu.Unlock()
	if s.revealCache == nil {
		s.revealCache = make(map[string]revealCacheEntry)
	}
	if s.revealInflight == nil {
		s.revealInflight = make(map[string]*revealInflight)
	}
	s.revealPruneLocked(now)
	entry, ok := s.revealCache[requestID]
	if !ok || !entry.expiresAt.After(now) {
		return revealCacheEntry{}, false, nil
	}
	if entry.actor != actor || entry.secretRef != secretRef {
		return revealCacheEntry{}, false, fmt.Errorf("HASP-Request-Id %q was already used for a different reveal request", requestID)
	}
	entry.body = append([]byte(nil), entry.body...)
	return entry, true, nil
}

func (s *rpcServer) revealPruneLocked(now time.Time) {
	for requestID, entry := range s.revealCache {
		if !entry.expiresAt.After(now) {
			delete(s.revealCache, requestID)
		}
	}
}

func (s *rpcServer) revealBegin(requestID string, actor string, secretRef string) (*revealInflight, bool, error) {
	now := time.Now().UTC()
	s.revealMu.Lock()
	defer s.revealMu.Unlock()
	s.revealPruneLocked(now)
	if entry, ok := s.revealCache[requestID]; ok && entry.expiresAt.After(now) {
		if entry.actor != actor || entry.secretRef != secretRef {
			return nil, false, fmt.Errorf("HASP-Request-Id %q was already used for a different reveal request", requestID)
		}
		return &revealInflight{entry: entry, done: closedRevealDone()}, false, nil
	}
	if existing, ok := s.revealInflight[requestID]; ok {
		if existing.actor != actor || existing.secretRef != secretRef {
			return nil, false, fmt.Errorf("HASP-Request-Id %q is already in use for a different reveal request", requestID)
		}
		return existing, false, nil
	}
	inflight := &revealInflight{
		actor:     actor,
		secretRef: secretRef,
		done:      make(chan struct{}),
	}
	s.revealInflight[requestID] = inflight
	return inflight, true, nil
}

func (s *rpcServer) revealFinish(requestID string, entry revealCacheEntry, err error) {
	s.revealMu.Lock()
	inflight := s.revealInflight[requestID]
	if inflight != nil {
		inflight.err = err
		if err == nil {
			inflight.entry = entry
			s.revealCache[requestID] = entry
		}
		delete(s.revealInflight, requestID)
		close(inflight.done)
	}
	s.revealMu.Unlock()
}

func closedRevealDone() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (s *rpcServer) allowReveal(actor string, now time.Time) bool {
	cutoff := now.Add(-revealRateLimitWindow)
	s.revealMu.Lock()
	defer s.revealMu.Unlock()
	existing := s.revealRates[actor]
	kept := existing[:0]
	for _, seen := range existing {
		if seen.After(cutoff) {
			kept = append(kept, seen)
		}
	}
	if len(kept) >= revealRateLimitCount {
		s.revealRates[actor] = kept
		return false
	}
	kept = append(kept, now)
	s.revealRates[actor] = kept
	return true
}

func (s *rpcServer) broker() *brokerRPC {
	return &brokerRPC{
		paths:       s.paths,
		startedAt:   s.startedAt,
		sessions:    s.sessions,
		approvals:   s.approvals,
		audit:       s.audit,
		auditState:  s.auditState,
		events:      s.events,
		keyring:     s.keyring,
		matrixInput: s.accessMatrixInput,
	}
}

func listLeasesRequestFromHTTP(r *http.Request) (ListLeasesRequest, error) {
	values := r.URL.Query()
	req := ListLeasesRequest{
		ConsumerID: strings.TrimSpace(values.Get("consumer")),
		Status:     strings.TrimSpace(values.Get("status")),
		Cursor:     strings.TrimSpace(values.Get("cursor")),
	}
	if req.ConsumerID == "" {
		req.ConsumerID = strings.TrimSpace(values.Get("consumer_id"))
	}
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			return ListLeasesRequest{}, fmt.Errorf("invalid limit %q", raw)
		}
		req.Limit = limit
	}
	if raw := strings.TrimSpace(values.Get("expiring_in")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return ListLeasesRequest{}, fmt.Errorf("invalid expiring_in %q", raw)
		}
		req.ExpiringInSeconds = int(d.Seconds())
	}
	return req, nil
}

func accessMatrixRequestFromHTTP(r *http.Request) (AccessMatrixRequest, error) {
	values := r.URL.Query()
	req := AccessMatrixRequest{
		Range:    strings.TrimSpace(values.Get("range")),
		Consumer: strings.TrimSpace(values.Get("consumer")),
		Secret:   strings.TrimSpace(values.Get("secret")),
		Scope:    strings.TrimSpace(values.Get("scope")),
		Source:   strings.TrimSpace(values.Get("source")),
		Cursor:   strings.TrimSpace(values.Get("cursor")),
	}
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 {
			return AccessMatrixRequest{}, fmt.Errorf("invalid limit %q", raw)
		}
		req.Limit = limit
	}
	if raw := strings.TrimSpace(values.Get("has_active_lease")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return AccessMatrixRequest{}, fmt.Errorf("invalid has_active_lease %q", raw)
		}
		req.HasActiveLease = &value
	}
	return req, nil
}

func leaseRevokeIDFromPath(path string) (string, bool) {
	const prefix = "/v1/leases/"
	const suffix = "/revoke"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix), "/")
	return id, id != ""
}

func approvalDecideIDFromPath(path string) (string, bool) {
	const prefix = "/v1/approvals/"
	const suffix = "/decide"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix), "/")
	return id, id != ""
}

func approvalDetailIDFromPath(path string) (string, bool) {
	const prefix = "/v1/approvals/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	id := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func integrationActionFromPath(path string) (string, string, bool) {
	const prefix = "/v1/integrations/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	targetID, err := url.PathUnescape(parts[0])
	if err != nil || strings.Contains(targetID, "/") || strings.TrimSpace(targetID) != targetID {
		return "", "", false
	}
	action, err := url.PathUnescape(parts[1])
	if err != nil || strings.Contains(action, "/") || strings.TrimSpace(action) != action {
		return "", "", false
	}
	if action != "profiles" && action != "doctor" {
		return "", "", false
	}
	return targetID, action, true
}

func integrationProfilePath(path string) (string, string, bool) {
	const prefix = "/v1/integrations/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] != "profiles" || parts[2] == "" {
		return "", "", false
	}
	targetID, err := url.PathUnescape(parts[0])
	if err != nil || strings.Contains(targetID, "/") || strings.TrimSpace(targetID) != targetID {
		return "", "", false
	}
	profileID, err := url.PathUnescape(parts[2])
	if err != nil || strings.Contains(profileID, "/") || strings.TrimSpace(profileID) != profileID {
		return "", "", false
	}
	return targetID, profileID, true
}

func decodeJSONObject(w http.ResponseWriter, r *http.Request, dst any, trailingMessage string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httpapi.WriteErrorEnvelope(w, http.StatusBadRequest, "bad_request", "Bad request", trailingMessage)
		return false
	}
	return true
}

func writeIntegrationProfileMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, integrations.ErrTargetNotFound), errors.Is(err, integrations.ErrProfileNotFound):
		httpapi.WriteErrorEnvelope(w, http.StatusNotFound, "integration_not_found", "Integration not found", err.Error())
	case errors.Is(err, integrations.ErrProfileConflict):
		httpapi.WriteErrorEnvelope(w, http.StatusConflict, "integration_profile_conflict", "Integration profile conflict", err.Error())
	case errors.Is(err, integrations.ErrProfileImmutable):
		httpapi.WriteErrorEnvelope(w, http.StatusConflict, "integration_profile_immutable", "Integration profile immutable", err.Error())
	case errors.Is(err, integrations.ErrProfileVersion):
		httpapi.WriteErrorEnvelope(w, http.StatusPreconditionFailed, "integration_profile_version_mismatch", "Integration profile version mismatch", err.Error())
	case errors.Is(err, integrations.ErrPreconditionRequired):
		httpapi.WriteErrorEnvelope(w, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "If-Match is required")
	case errors.Is(err, integrations.ErrProfileInvalid):
		httpapi.WriteErrorEnvelope(w, http.StatusUnprocessableEntity, "integration_profile_invalid", "Integration profile invalid", err.Error())
	default:
		httpapi.WriteErrorEnvelope(w, http.StatusInternalServerError, "integration_profile_failed", "Integration profile failed", err.Error())
	}
	return true
}

func (s *rpcServer) handleHTTPEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.WriteErrorEnvelope(w, http.StatusMethodNotAllowed, "method_not_allowed", http.StatusText(http.StatusMethodNotAllowed), "GET is required")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	if flusher, ok := w.(http.Flusher); ok {
		topics := requestedEventTopicSet(r)
		_, _ = fmt.Fprint(w, ": connected\n\n")
		flusher.Flush()
		sub := s.events.subscribe()
		defer s.events.unsubscribe(sub)
		for _, event := range s.events.replaySince(r.Header.Get("Last-Event-ID")) {
			if len(topics) > 0 && !topics[event.Name] {
				continue
			}
			writeRuntimeSSE(w, event)
		}
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case event, ok := <-sub:
				if !ok {
					return
				}
				if len(topics) > 0 && !topics[event.Name] {
					continue
				}
				writeRuntimeSSE(w, event)
				flusher.Flush()
			}
		}
	} else {
		_, _ = fmt.Fprint(w, ": connected\n\n")
	}
}

func auditLimitFromHTTP(r *http.Request) (int, error) {
	limit := 10
	if r == nil || r.URL == nil {
		return limit, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return limit, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid limit %q", raw)
	}
	if parsed > 100_000 {
		parsed = 100_000
	}
	return parsed, nil
}

func auditExportOptionsFromHTTP(r *http.Request) (auditops.ExportOptions, error) {
	var opts auditops.ExportOptions
	if r == nil || r.URL == nil {
		return opts, nil
	}
	if format := strings.TrimSpace(r.URL.Query().Get("format")); format != "" && format != "ndjson" {
		return opts, fmt.Errorf("unsupported format %q", format)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("from")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return opts, fmt.Errorf("invalid from %q", raw)
		}
		opts.From = parsed
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("to")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return opts, fmt.Errorf("invalid to %q", raw)
		}
		opts.To = parsed
	}
	if !opts.From.IsZero() && !opts.To.IsZero() && opts.To.Before(opts.From) {
		return opts, errors.New("to must be greater than or equal to from")
	}
	return opts, nil
}

func (s *rpcServer) auditListSnapshot(limit int) (AuditListResponse, error) {
	if s.audit == nil {
		return AuditListResponse{}, errors.New("audit logger unavailable")
	}
	events, err := s.audit.Events()
	if err != nil {
		s.auditState.RecordAppendResult(err)
		return AuditListResponse{}, err
	}
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}
	start := len(events) - limit
	entries := make([]AuditEntry, 0, limit)
	for i := len(events) - 1; i >= start; i-- {
		entries = append(entries, auditEntryFromEvent(events[i]))
	}
	return AuditListResponse{Schema: 1, Entries: entries}, nil
}

func (s *rpcServer) approvalDetailSnapshot(id string) (ApprovalDetailResponse, error) {
	if s.approvals == nil {
		return ApprovalDetailResponse{}, errors.New("approval store unavailable")
	}
	var selected Approval
	for _, approval := range s.approvals.Snapshot() {
		if approval.ID == id {
			selected = approval
			break
		}
	}
	if selected.ID == "" {
		return ApprovalDetailResponse{}, errors.New("approval not found")
	}
	historyResponse := approvals.List(s.approvals.Snapshot(), approvals.ListOptions{
		ConsumerID: selected.RequesterConsumerID,
		Now:        time.Now().UTC(),
	})
	auditTrail := []AuditEntry{}
	if s.audit != nil {
		if events, err := s.audit.Events(); err == nil {
			for i := len(events) - 1; i >= 0 && len(auditTrail) < 20; i-- {
				entry := auditEntryFromEvent(events[i])
				if strings.Contains(entry.Target, selected.ID) ||
					strings.Contains(entry.Target, selected.RequesterConsumerID) ||
					strings.Contains(entry.Target, selected.SecretID) ||
					(entry.Action == "approval.decide" && strings.Contains(entry.Target, selected.ID)) {
					auditTrail = append(auditTrail, entry)
				}
			}
		}
	}
	return ApprovalDetailResponse{
		Approval:          selected,
		RequesterVerifier: selected.RequesterVerifier,
		ConsumerHistory:   historyResponse.Approvals,
		AuditTrail:        auditTrail,
		GeneratedAt:       time.Now().UTC(),
	}, nil
}

func (s *rpcServer) auditVerifySnapshot(force bool) (AuditVerifyResponse, error) {
	if s.audit == nil {
		return AuditVerifyResponse{}, errors.New("audit logger unavailable")
	}
	verifiedAt := time.Now().UTC()
	s.auditVerifyMu.Lock()
	if !force && !s.auditVerifyCachedAt.IsZero() && verifiedAt.Sub(s.auditVerifyCachedAt) < 30*time.Second {
		cached := s.auditVerifyCached
		s.auditVerifyMu.Unlock()
		return cached, nil
	}
	s.auditVerifyMu.Unlock()
	report, err := auditops.Verify(s.audit, verifiedAt)
	if err != nil {
		s.auditState.RecordAppendResult(err)
		return AuditVerifyResponse{}, err
	}
	reply := AuditVerifyResponse{
		Schema:            jsonwire.SchemaVersion,
		ChainOK:           report.ChainOK,
		LastVerifiedAt:    report.LastVerifiedAt,
		TotalEntries:      report.TotalEntries,
		FirstCorruptionAt: report.FirstCorruptionAt,
		Error:             report.Error,
		OK:                report.ChainOK,
		CheckedCount:      report.TotalEntries,
	}
	if !report.ChainOK {
		s.auditState.MarkVerifyFailedAt(time.Now().UTC())
		s.auditVerifyMu.Lock()
		s.auditVerifyCached = reply
		s.auditVerifyCachedAt = verifiedAt
		s.auditVerifyMu.Unlock()
		return reply, nil
	}
	s.auditState.MarkVerifiedAt(verifiedAt)
	s.auditVerifyMu.Lock()
	s.auditVerifyCached = reply
	s.auditVerifyCachedAt = verifiedAt
	s.auditVerifyMu.Unlock()
	return reply, nil
}

func (s *rpcServer) auditExportNDJSON(w io.Writer, opts auditops.ExportOptions) error {
	if s.audit == nil {
		return errors.New("audit logger unavailable")
	}
	events, err := s.audit.Events()
	if err != nil {
		s.auditState.RecordAppendResult(err)
		return err
	}
	trailerKey := s.httpRevealKey()
	if len(trailerKey) == 0 {
		trailerKey = s.audit.HMACKey()
	}
	_, err = auditops.ExportNDJSON(w, events, opts, trailerKey)
	return err
}

func auditEntryFromEvent(event audit.Event) AuditEntry {
	action := event.Type
	target := ""
	if raw, ok := event.Details["action"].(string); ok && strings.TrimSpace(raw) != "" {
		action = strings.TrimSpace(raw)
	}
	for _, key := range []string{"target", "secret_id", "item", "item_name", "name", "lease_id", "approval_id", "session_id", "binding_id", "project_root", "consumer_id"} {
		if raw, ok := event.Details[key].(string); ok && strings.TrimSpace(raw) != "" {
			target = strings.TrimSpace(raw)
			break
		}
	}
	details := ""
	if len(event.Details) > 0 {
		if data, err := json.Marshal(event.Details); err == nil {
			details = string(data)
		}
	}
	return AuditEntry{
		ID:        strconv.FormatInt(event.Sequence, 10),
		Sequence:  event.Sequence,
		Timestamp: event.Timestamp,
		Type:      event.Type,
		Action:    action,
		Actor:     event.Actor,
		Target:    target,
		Details:   details,
		Hash:      event.Hash,
	}
}

func requestedEventTopics(r *http.Request) []string {
	if r == nil || r.URL == nil {
		return nil
	}
	values := r.URL.Query()
	rawTopics := values["topic"]
	rawTopics = append(rawTopics, values["topics"]...)
	topics := make([]string, 0, len(rawTopics))
	for _, raw := range rawTopics {
		for _, topic := range strings.Split(raw, ",") {
			topic = strings.TrimSpace(topic)
			if topic != "" {
				topics = append(topics, topic)
			}
		}
	}
	return topics
}

func requestedEventTopicSet(r *http.Request) map[string]bool {
	topics := requestedEventTopics(r)
	if len(topics) == 0 {
		return nil
	}
	set := make(map[string]bool, len(topics))
	for _, topic := range topics {
		set[topic] = true
	}
	return set
}

func writeRuntimeSSE(w io.Writer, event runtimeEvent) {
	_, _ = fmt.Fprintf(w, "event: %s\n", event.Name)
	if event.ID != "" {
		_, _ = fmt.Fprintf(w, "id: %s\n", event.ID)
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", event.Data)
}

type runtimeEvent struct {
	ID   string
	Name string
	Data string
}

type runtimeEventHub struct {
	mu          sync.Mutex
	subscribers map[chan runtimeEvent]struct{}
	history     []runtimeEvent
	nextID      uint64
	maxHistory  int
}

func newRuntimeEventHub() *runtimeEventHub {
	return &runtimeEventHub{subscribers: make(map[chan runtimeEvent]struct{}), maxHistory: 256}
}

func (h *runtimeEventHub) subscribe() chan runtimeEvent {
	ch := make(chan runtimeEvent, 8)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *runtimeEventHub) unsubscribe(ch chan runtimeEvent) {
	h.mu.Lock()
	if _, ok := h.subscribers[ch]; ok {
		delete(h.subscribers, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *runtimeEventHub) replaySince(lastID string) []runtimeEvent {
	if h == nil || strings.TrimSpace(lastID) == "" {
		return nil
	}
	last, err := strconv.ParseUint(strings.TrimSpace(lastID), 10, 64)
	if err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]runtimeEvent, 0, len(h.history))
	for _, event := range h.history {
		id, err := strconv.ParseUint(event.ID, 10, 64)
		if err == nil && id > last {
			out = append(out, event)
		}
	}
	return out
}

func (h *runtimeEventHub) publish(name string, data string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.nextID++
	event := runtimeEvent{ID: strconv.FormatUint(h.nextID, 10), Name: name, Data: data}
	h.history = append(h.history, event)
	if len(h.history) > h.maxHistory {
		h.history = h.history[len(h.history)-h.maxHistory:]
	}
	for subscriber := range h.subscribers {
		select {
		case subscriber <- event:
		default:
			delete(h.subscribers, subscriber)
			close(subscriber)
		}
	}
	h.mu.Unlock()
}

func hmacValidatorMiddleware(validator *httpapi.Validator, recorder httpapi.AttestationFailureRecorder, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if validator == nil {
			next.ServeHTTP(w, r)
			return
		}
		if err := validator.Validate(r); err != nil {
			if httpapi.IsRevealRequest(r) {
				if recorder != nil {
					recorder(r, err)
				}
				httpapi.WriteErrorEnvelope(w, http.StatusForbidden, "forbidden", http.StatusText(http.StatusForbidden), err.Error())
				return
			}
			httpapi.WriteErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "Unauthorized", err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

func revealSecretRef(r *http.Request) (string, error) {
	ref, ok, err := httpapi.RevealSecretRef(r)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("not a reveal route")
	}
	return ref, nil
}

func revealActor(r *http.Request) string {
	pid, err := httpapi.PeerPIDFromContext(r)
	if err == nil && pid > 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	return "pid:unknown"
}

func isUUIDV7(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
				return false
			}
		}
	}
	return value[14] == '7'
}

func defaultRevealItem(ctx context.Context, runtimePaths paths.Paths, secretRef string) (revealcore.Payload, error) {
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		return revealcore.Payload{}, err
	}
	handle, err := vaultStore.OpenWithConvenienceUnlock(ctx)
	if err != nil {
		return revealcore.Payload{}, err
	}
	return revealcore.Find(handle, secretRef)
}

func defaultValidateVaultUnlock(ctx context.Context, runtimePaths paths.Paths) error {
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		return err
	}
	handle, err := vaultStore.OpenWithConvenienceUnlock(ctx)
	if err != nil {
		return err
	}
	_ = handle
	return nil
}

func defaultAccessMatrixInput(ctx context.Context, runtimePaths paths.Paths, sessions *SessionStore) (accessmatrix.Input, error) {
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		return accessmatrix.Input{}, err
	}
	handle, err := openAccessMatrixHandle(ctx, vaultStore)
	if err != nil {
		return accessmatrix.Input{}, err
	}
	return accessMatrixInputFromHandle(handle, sessions), nil
}

func openAccessMatrixHandle(ctx context.Context, vaultStore *store.Store) (*store.Handle, error) {
	if password := os.Getenv("HASP_MASTER_PASSWORD"); strings.TrimSpace(password) != "" {
		return vaultStore.OpenWithPassword(ctx, password)
	}
	return vaultStore.OpenWithConvenienceUnlock(ctx)
}

func openRuntimeVaultHandle(ctx context.Context, runtimePaths paths.Paths) (*store.Handle, error) {
	vaultStore, err := store.NewForPaths(store.NewDefaultKeyring(), runtimePaths)
	if err != nil {
		return nil, err
	}
	return openAccessMatrixHandle(ctx, vaultStore)
}

func accessMatrixInputFromHandle(handle *store.Handle, sessions *SessionStore) accessmatrix.Input {
	input := accessmatrix.Input{
		AppConsumers:    handle.ListAppConsumers(),
		AgentConsumers:  handle.ListAgentConsumers(),
		Items:           handle.ListItemMetadata(),
		ProjectLeases:   handle.ListProjectLeases(),
		SecretGrants:    handle.ListSecretGrants(),
		PlaintextGrants: handle.ListPlaintextGrants(),
		MutationGrants:  handle.ListMutationGrants(),
		Now:             time.Now().UTC(),
	}
	if sessions == nil {
		return input
	}
	for _, session := range sessions.Snapshot() {
		input.Sessions = append(input.Sessions, accessmatrix.Session{
			Token:      session.Token,
			ConsumerID: sessionConsumerID(session),
		})
	}
	input.Leases = sessions.LeaseSnapshot()
	return input
}

func newHASPAppAttestor() (httpapi.Attestor, error) {
	teamID := strings.TrimSpace(httpapi.HMACTeamID)
	if teamID == "" && isGoTestBinary() {
		teamID = "TEAMID1234"
	}
	requirement, err := httpapi.HASPAppDesignatedRequirement(teamID)
	if err != nil {
		return nil, err
	}
	return httpapi.NewDesignatedRequirementAttestor(requirement)
}

func defaultHTTPHMACKey(ctx context.Context) ([]byte, error) {
	key, err := httpapi.LoadProvisionedHMACKey(store.NewDefaultKeyring())
	if err == nil {
		return key, nil
	}
	if isGoTestBinary() || os.Getenv(paths.EnvTest) == "1" {
		key := make([]byte, sha256.Size)
		if _, randErr := rand.Read(key); randErr != nil {
			return nil, fmt.Errorf("generate test HTTP HMAC key: %w", randErr)
		}
		return key, nil
	}
	return nil, err
}

func isGoTestBinary() bool {
	return strings.HasSuffix(os.Args[0], ".test")
}

func normalizeHTTPPaths(runtimePaths paths.Paths) paths.Paths {
	normalized := runtimePaths
	explicitHTTPUnixSocketPath := strings.TrimSpace(runtimePaths.HTTPUnixSocketPath) != ""
	if normalized.HomeDir == "" {
		switch {
		case normalized.HTTPPortFilePath != "":
			normalized.HomeDir = filepath.Dir(normalized.HTTPPortFilePath)
		case normalized.RuntimeDir != "":
			normalized.HomeDir = normalized.RuntimeDir
		default:
			normalized.HomeDir = os.TempDir()
		}
	}
	if normalized.HTTPPortFilePath == "" {
		normalized.HTTPPortFilePath = filepath.Join(normalized.HomeDir, httpapi.PortFileName)
	}
	if normalized.RuntimeDir == "" {
		normalized.RuntimeDir = filepath.Join(normalized.HomeDir, "runtime")
	}
	if normalized.HTTPUnixSocketPath == "" {
		normalized.HTTPUnixSocketPath = filepath.Join(normalized.RuntimeDir, "daemon.http.sock")
	}
	if isGoTestBinary() || os.Getenv(paths.EnvTest) == "1" {
		if socketOverride := strings.TrimSpace(os.Getenv(paths.EnvSocket)); socketOverride != "" && socketOverride == normalized.SocketPath {
			normalized.HTTPPortFilePath = socketOverride + ".http.port"
			normalized.HTTPUnixSocketPath = socketOverride + ".http.sock"
		} else if normalized.SocketPath != "" {
			if runtimePaths.HTTPPortFilePath == "" {
				normalized.HTTPPortFilePath = normalized.SocketPath + ".http.port"
			}
			if !explicitHTTPUnixSocketPath {
				normalized.HTTPUnixSocketPath = normalized.SocketPath + ".http.sock"
			}
		}
	}
	return normalized
}

func httpSidecarPaths(runtimePaths paths.Paths) []string {
	normalized := normalizeHTTPPaths(runtimePaths)
	seen := map[string]bool{}
	sidecars := make([]string, 0, 2)
	for _, path := range []string{normalized.HTTPPortFilePath, normalized.HTTPUnixSocketPath} {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		sidecars = append(sidecars, path)
	}
	return sidecars
}

type rpcServer struct {
	startedAt  time.Time
	paths      paths.Paths
	server     *rpc.Server
	sessions   *SessionStore
	approvals  *ApprovalStore
	audit      *audit.Log
	auditState *AuditState
	events     *runtimeEventHub
	stopOnce   sync.Once
	// peerUID and peerPID are the peer-credential lookups. Production
	// builds wire them to realPeerUID / realPeerPID via newRPCServer; tests
	// override them locally on a server instance instead of swapping
	// package-level vars under a global mutex.
	peerUID             func(net.Conn) (uint32, error)
	peerPID             func(net.Conn) (uint32, error)
	httpMu              sync.RWMutex
	httpListener        dashboard.HTTPListener
	httpHMACKey         []byte
	keyring             store.Keyring
	revealItem          func(context.Context, paths.Paths, string) (revealcore.Payload, error)
	validateVaultUnlock func(context.Context, paths.Paths) error
	accessMatrixInput   func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error)
	revealMu            sync.Mutex
	revealCache         map[string]revealCacheEntry
	revealInflight      map[string]*revealInflight
	revealRates         map[string][]time.Time
	masterPasswordMu    sync.Mutex
	masterPasswordRates map[string][]time.Time
	auditVerifyMu       sync.Mutex
	auditVerifyCached   AuditVerifyResponse
	auditVerifyCachedAt time.Time
}

func buildDashboardPayload(startedAt time.Time, sessions *SessionStore, auditState *AuditState, httpListener dashboard.HTTPListener, pendingApprovals int, oldestApprovalS int) dashboard.Payload {
	sessionViews := sessions.ViewSnapshot()
	visibleSessions := sessions.VisibleSnapshot()
	auditDegraded, degradedAt := auditState.Snapshot()
	now := sessions.now().UTC()
	dashboardSessions := make([]dashboard.Session, 0, len(sessionViews))
	for _, session := range sessionViews {
		dashboardSessions = append(dashboardSessions, dashboard.Session{
			OpenedAt:   session.OpenedAt,
			LastSeenAt: session.LastSeenAt,
			ExpiresAt:  session.ExpiresAt,
		})
	}
	visibleDashboardSessions := make([]dashboard.Session, 0, len(visibleSessions))
	for _, session := range visibleSessions {
		visibleDashboardSessions = append(visibleDashboardSessions, dashboard.Session{
			OpenedAt:   session.OpenedAt,
			LastSeenAt: session.LastSeenAt,
			ExpiresAt:  session.ExpiresAt,
		})
	}
	return dashboard.Build(dashboard.Input{
		Now:                 now,
		StartedAt:           startedAt,
		Sessions:            dashboardSessions,
		VisibleSessions:     visibleDashboardSessions,
		IdleTTL:             sessions.idleTTL,
		AuditDegraded:       auditDegraded,
		AuditDegradedAt:     degradedAt,
		PendingApprovals:    pendingApprovals,
		OldestApprovalS:     oldestApprovalS,
		Version:             Version,
		HTTPListener:        httpListener,
		AuditLastVerifiedAt: auditState.LastVerifiedAt(),
	})
}

func buildStatusResponse(runtimePaths paths.Paths, startedAt time.Time, sessions *SessionStore, auditState *AuditState, httpListener dashboard.HTTPListener, pendingApprovals int, oldestApprovalS int) StatusResponse {
	sessionViews := sessions.ViewSnapshot()
	auditDegraded, degradedAt := auditState.Snapshot()
	processIdentityDegraded, processIdentityReason := sessions.ProcessIdentityDegraded()
	dashboardPayload := buildDashboardPayload(startedAt, sessions, auditState, httpListener, pendingApprovals, oldestApprovalS)

	auditHealth := "ok"
	if auditDegraded {
		auditHealth = "degraded"
	}

	return StatusResponse{
		SocketPath:                    runtimePaths.SocketPath,
		PID:                           os.Getpid(),
		StartedAt:                     startedAt,
		ActiveSessions:                len(sessionViews),
		Sessions:                      sessionViews,
		AuditDegraded:                 auditDegraded,
		AuditDegradedAt:               degradedAt,
		ProcessIdentityDegraded:       processIdentityDegraded,
		ProcessIdentityDegradedReason: processIdentityReason,
		LeasesCount:                   len(sessionViews),
		ApprovalsPending:              pendingApprovals,
		Expiring30m:                   dashboardPayload.Leases.ExpiringSoon,
		AuditHealth:                   auditHealth,
		Vault:                         dashboardPayload.Vault,
		Leases:                        dashboardPayload.Leases,
		Approvals:                     dashboardPayload.Approvals,
		Audit:                         dashboardPayload.Audit,
		Integrations:                  dashboardPayload.Integrations,
		Daemon:                        dashboardPayload.Daemon,
	}
}

func (b *brokerRPC) statusSnapshot() StatusResponse {
	pending, oldest := approvalStats(b.approvals)
	return buildStatusResponse(b.paths, b.startedAt, b.sessions, b.auditState, dashboard.HTTPListener{}, pending, oldest)
}

func newRPCServer(runtimePaths paths.Paths) *rpcServer {
	startedAt := time.Now().UTC()
	log, logErr := newRuntimeAuditLog()
	if log != nil {
		log = log.WithKey(auditlog.GetHMACKey())
	}
	auditState := newAuditState(nil)
	if logErr != nil {
		auditState.MarkDegradedAt(startedAt)
	}
	approvalStore := NewApprovalStore()
	server := &rpcServer{
		startedAt:           startedAt,
		paths:               runtimePaths,
		server:              rpc.NewServer(),
		sessions:            NewSessionStore(),
		approvals:           approvalStore,
		audit:               log,
		auditState:          auditState,
		events:              newRuntimeEventHub(),
		peerUID:             realPeerUID,
		peerPID:             realPeerPID,
		keyring:             store.NewDefaultKeyring(),
		revealItem:          defaultRevealItem,
		validateVaultUnlock: defaultValidateVaultUnlock,
		accessMatrixInput:   defaultAccessMatrixInput,
		revealCache:         make(map[string]revealCacheEntry),
		revealInflight:      make(map[string]*revealInflight),
		revealRates:         make(map[string][]time.Time),
		masterPasswordRates: make(map[string][]time.Time),
	}
	approvalStore.SetOnQueue(server.publishQueuedApproval)
	return server
}

func (s *rpcServer) publishQueuedApproval(approval approvals.Approval) {
	if s.events == nil {
		return
	}
	s.events.publish("approvals.changed", fmt.Sprintf(`{"approval_id":%q,"status":"pending"}`, approval.ID))
	s.events.publish("dashboard.changed", `{"source":"approval.queue"}`)
}

func (s *rpcServer) register() error {
	return registerServerName(s.server, "HASP", &brokerRPC{
		paths:       s.paths,
		startedAt:   s.startedAt,
		sessions:    s.sessions,
		approvals:   s.approvals,
		audit:       s.audit,
		auditState:  s.auditState,
		events:      s.events,
		matrixInput: s.accessMatrixInput,
	})
}

// serve is the daemon's RPC accept loop. The trust boundary for the daemon
// is a peer-UID check on every Accept: socket-file mode 0o600 alone does not
// protect against same-UID processes dialing the socket, so we verify the
// connecting peer's effective UID via SO_PEERCRED (Linux) / LOCAL_PEERCRED
// (Darwin) and fail closed on mismatch or lookup failure.
func (s *rpcServer) serve(ctx context.Context, listener net.Listener) error {
	expectedUID := uint32(os.Geteuid())
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}

		peerUID, peerErr := s.peerUID(conn)
		if peerErr != nil {
			_ = conn.Close()
			s.appendPeerRejectAudit(map[string]any{
				"action": "peer.reject",
				"reason": "lookup_failed",
				"error":  peerErr.Error(),
			})
			continue
		}
		if peerUID != expectedUID {
			_ = conn.Close()
			s.appendPeerRejectAudit(map[string]any{
				"action":       "peer.reject",
				"reason":       "mismatched_uid",
				"peer_uid":     peerUID,
				"expected_uid": expectedUID,
			})
			continue
		}

		// Capture peer PID per-connection. s.peerPID errors are NOT a hard
		// reject at accept (some platforms / kernels may not surface PID even
		// when UID is fine) — instead we stamp peerPID = 0, which makes
		// privileged operations like RegisterProcess fail closed inside the
		// handler. Read-only RPCs (Ping/Status) still work.
		peerPID, pidErr := s.peerPID(conn)
		if pidErr != nil {
			peerPID = 0
		}

		go s.serveConn(conn, peerPID)
	}
}

func (s *rpcServer) serveConn(conn net.Conn, peerPID uint32) {
	perConn := rpc.NewServer()
	bound := &brokerRPC{
		paths:       s.paths,
		startedAt:   s.startedAt,
		sessions:    s.sessions,
		approvals:   s.approvals,
		audit:       s.audit,
		auditState:  s.auditState,
		events:      s.events,
		peerPID:     peerPID,
		matrixInput: s.accessMatrixInput,
	}
	if err := registerServerName(perConn, "HASP", bound); err != nil {
		_ = conn.Close()
		return
	}
	perConn.ServeCodec(jsonrpc.NewServerCodec(conn))
}

func (s *rpcServer) statusSnapshot() StatusResponse {
	s.httpMu.RLock()
	httpListener := s.httpListener
	s.httpMu.RUnlock()
	pending, oldest := approvalStats(s.approvals)
	return buildStatusResponse(s.paths, s.startedAt, s.sessions, s.auditState, httpListener, pending, oldest)
}

func (s *rpcServer) dashboardSnapshot() (dashboard.Response, error) {
	if s.sessions == nil || s.auditState == nil {
		return dashboard.Response{}, errors.New("vault state source is unavailable")
	}
	s.httpMu.RLock()
	httpListener := s.httpListener
	s.httpMu.RUnlock()
	pending, oldest := approvalStats(s.approvals)
	return dashboard.Response{
		Schema:  jsonwire.SchemaVersion,
		Payload: buildDashboardPayload(s.startedAt, s.sessions, s.auditState, httpListener, pending, oldest),
	}, nil
}

func (s *rpcServer) secretsListSnapshot(ctx context.Context) (SecretsListResponse, error) {
	input, err := defaultAccessMatrixInput(ctx, s.paths, nil)
	if err != nil {
		return SecretsListResponse{}, err
	}
	lastRevealed, err := s.secretLastRevealed()
	if err != nil {
		return SecretsListResponse{}, err
	}
	secrets := make([]SecretListItem, 0, len(input.Items))
	for _, item := range input.Items {
		folder, name := splitSecretPath(item.Name)
		secrets = append(secrets, SecretListItem{
			ID:           item.ID,
			Name:         name,
			Path:         folder,
			Ref:          item.Name,
			Kind:         string(item.Kind),
			Policy:       string(item.Metadata.Policy),
			Version:      item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			LastModified: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
			LastRevealed: lastRevealed[item.ID],
			Tags:         append([]string(nil), item.Metadata.Tags...),
		})
	}
	return SecretsListResponse{Schema: jsonwire.SchemaVersion, Secrets: secrets}, nil
}

func splitSecretPath(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "Vault", ""
	}
	slash := strings.LastIndex(ref, "/")
	if slash < 0 {
		return "Vault", ref
	}
	name := strings.TrimSpace(ref[slash+1:])
	if name == "" {
		name = ref
	}
	return ref[:slash], name
}

func (s *rpcServer) secretLastRevealed() (map[string]string, error) {
	result := map[string]string{}
	if s.audit == nil {
		return result, nil
	}
	events, err := s.audit.Events()
	if err != nil {
		s.auditState.RecordAppendResult(err)
		return nil, err
	}
	for _, event := range events {
		if event.Type != audit.EventRead || event.Details["action"] != "secret.reveal" {
			continue
		}
		itemID, _ := event.Details["item_id"].(string)
		if itemID == "" {
			continue
		}
		result[itemID] = event.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	return result, nil
}

func approvalStats(store *ApprovalStore) (int, int) {
	if store == nil {
		return 0, 0
	}
	reply := approvals.List(store.Snapshot(), approvals.ListOptions{Now: time.Now().UTC()})
	return reply.PendingCount, reply.OldestPendingAgeS
}

func (s *rpcServer) vaultStatusSnapshot() VaultStatusResponse {
	if s.sessions.IsLocked() {
		return VaultStatusResponse{Schema: jsonwire.SchemaVersion, State: "locked", Locked: true}
	}
	sessions := s.sessions.ViewSnapshot()
	if len(sessions) == 0 {
		return VaultStatusResponse{Schema: jsonwire.SchemaVersion, State: "locked", Locked: true}
	}
	now := time.Now().UTC()
	var latest time.Time
	for _, session := range sessions {
		if session.ExpiresAt.After(latest) {
			latest = session.ExpiresAt
		}
	}
	remaining := latest.Sub(now).Seconds()
	if remaining < 0 {
		remaining = 0
	}
	return VaultStatusResponse{
		Schema:       jsonwire.SchemaVersion,
		State:        "unlocked",
		Locked:       false,
		RemainingTTL: remaining,
	}
}

func (s *rpcServer) stop() {
	s.stopOnce.Do(func() {
		s.sessions.PruneExpired()
	})
}

// appendPeerRejectAudit records a peer rejection audit event. It guards for a
// nil audit logger so that rejection is still fail-closed even when the audit
// subsystem failed to initialise.
func (s *rpcServer) appendPeerRejectAudit(details map[string]any) {
	if s.audit == nil {
		s.auditState.RecordAppendResult(errors.New("audit logger unavailable"))
		return
	}
	_, err := s.audit.Append(audit.EventDeny, "daemon", details)
	s.auditState.RecordAppendResult(err)
}

func (s *rpcServer) recordAttestationFailure(r *http.Request, failure error) {
	details := map[string]any{
		"action": "transport.attestation.failed",
		"path":   "",
		"error":  failure.Error(),
	}
	if r != nil && r.URL != nil {
		details["path"] = r.URL.EscapedPath()
	}
	s.appendPeerRejectAudit(details)
}

const (
	masterPasswordFailureWindow   = 5 * time.Minute
	masterPasswordFailureLimit    = 3
	masterPasswordRateLimitAction = "vault.master_password.change"
	httpKeyFingerprintAction      = "daemon.http_key.fingerprint"
)

func (s *rpcServer) masterPasswordCallerKey(r *http.Request) string {
	if pid, err := httpapi.PeerPIDFromContext(r); err == nil && pid > 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	if r != nil {
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err == nil && host != "" {
			return "remote:" + host
		}
		if remote := strings.TrimSpace(r.RemoteAddr); remote != "" {
			return "remote:" + remote
		}
	}
	return "remote:unknown"
}

func (s *rpcServer) masterPasswordAuditDetails(r *http.Request) map[string]any {
	return s.httpAuditDetails(r, masterPasswordRateLimitAction)
}

func (s *rpcServer) httpAuditDetails(r *http.Request, action string) map[string]any {
	details := map[string]any{
		"action": action,
	}
	if r == nil {
		return details
	}
	if r.URL != nil {
		details["path"] = r.URL.EscapedPath()
	}
	if remote := strings.TrimSpace(r.RemoteAddr); remote != "" {
		details["remote_addr"] = remote
	}
	if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
		details["user_agent"] = ua
	}
	if pid, err := httpapi.PeerPIDFromContext(r); err == nil && pid > 0 {
		details["peer_pid"] = pid
	}
	return details
}

func (s *rpcServer) masterPasswordRetryAfter(callerKey string, now time.Time) time.Duration {
	if s == nil {
		return 0
	}
	s.masterPasswordMu.Lock()
	defer s.masterPasswordMu.Unlock()
	if s.masterPasswordRates == nil {
		s.masterPasswordRates = make(map[string][]time.Time)
	}
	attempts := recentAttempts(s.masterPasswordRates[callerKey], now, masterPasswordFailureWindow)
	s.masterPasswordRates[callerKey] = attempts
	if len(attempts) < masterPasswordFailureLimit {
		return 0
	}
	retryAfter := attempts[0].Add(masterPasswordFailureWindow).Sub(now)
	if retryAfter < time.Second {
		return time.Second
	}
	return retryAfter
}

func (s *rpcServer) recordMasterPasswordFailure(callerKey string, now time.Time) {
	if s == nil {
		return
	}
	s.masterPasswordMu.Lock()
	defer s.masterPasswordMu.Unlock()
	if s.masterPasswordRates == nil {
		s.masterPasswordRates = make(map[string][]time.Time)
	}
	attempts := recentAttempts(s.masterPasswordRates[callerKey], now, masterPasswordFailureWindow)
	attempts = append(attempts, now)
	s.masterPasswordRates[callerKey] = attempts
}

func (s *rpcServer) clearMasterPasswordFailures(callerKey string) {
	if s == nil {
		return
	}
	s.masterPasswordMu.Lock()
	defer s.masterPasswordMu.Unlock()
	delete(s.masterPasswordRates, callerKey)
}

func recentAttempts(attempts []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	filtered := attempts[:0]
	for _, attempt := range attempts {
		if !attempt.Before(cutoff) {
			filtered = append(filtered, attempt)
		}
	}
	return filtered
}

func (s *rpcServer) appendMasterPasswordAudit(eventType string, details map[string]any) {
	s.appendDaemonSecurityAudit(eventType, details)
}

func (s *rpcServer) appendDaemonSecurityAudit(eventType string, details map[string]any) {
	if s == nil {
		return
	}
	log := audit.NewForPaths(s.paths)
	_, err := log.Append(eventType, "daemon", details)
	if s.auditState != nil {
		s.auditState.RecordAppendResult(err)
	}
	if err == nil && s.events != nil {
		s.events.publish("audit.changed", fmt.Sprintf(`{"type":%q}`, eventType))
	}
}

func installAuditHMACKey(log *audit.Log, key []byte) error {
	if log == nil || len(key) == 0 {
		return nil
	}
	if len(key) != sha256.Size {
		return errors.New("audit HMAC key must be 32 bytes")
	}
	verifier, err := newRuntimeAuditLog()
	if err != nil {
		return fmt.Errorf("verify audit HMAC key: %w", err)
	}
	events, err := verifier.Events()
	if err != nil {
		return fmt.Errorf("verify audit HMAC key: %w", err)
	}
	trustedKeyedEvent := false
	for _, event := range events {
		if event.Scheme == audit.SchemeHMACSHA256V1 {
			trustedKeyedEvent = true
			break
		}
	}
	if !trustedKeyedEvent {
		return errors.New("audit HMAC key cannot be adopted before an existing keyed audit chain is present")
	}
	if err := verifier.WithKey(key).Verify(); err != nil {
		return fmt.Errorf("audit HMAC key does not verify existing audit chain: %w", err)
	}
	log.WithKey(key)
	return nil
}

type brokerRPC struct {
	paths       paths.Paths
	startedAt   time.Time
	sessions    *SessionStore
	approvals   *ApprovalStore
	audit       *audit.Log
	auditState  *AuditState
	events      *runtimeEventHub
	keyring     store.Keyring
	matrixInput func(context.Context, paths.Paths, *SessionStore) (accessmatrix.Input, error)
	// peerPID is the PID of the unix-socket peer for this connection, captured
	// at accept time via SO_PEERCRED / LOCAL_PEERPID. Zero means "unknown" —
	// either the lookup failed or this brokerRPC was registered on the shared
	// rpc.Server (legacy/template path). Privileged operations that depend on
	// peer identity (RegisterProcess) fail closed when peerPID is zero.
	peerPID uint32
}

func (b *brokerRPC) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{
		Name:       "hasp",
		Version:    VersionString(),
		ServerTime: time.Now().UTC(),
	}
	return nil
}

func (b *brokerRPC) Status(_ StatusRequest, reply *StatusResponse) error {
	*reply = b.statusSnapshot()
	return nil
}

func (b *brokerRPC) OpenSession(req OpenSessionRequest, reply *OpenSessionResponse) error {
	if req.HostLabel == "" {
		return errors.New("host_label is required")
	}
	var ttl time.Duration
	if req.TTLMillis > 0 {
		ttl = time.Duration(req.TTLMillis) * time.Millisecond
	} else {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl <= 0 || ttl > DefaultSessionTTL {
		ttl = DefaultSessionTTL
	}
	if err := installAuditHMACKey(b.audit, req.AuditHMACKey); err != nil {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action": "session.open.reject",
			"reason": "untrusted_audit_hmac_key",
		})
		return err
	}
	var session Session
	var err error
	if req.Internal {
		session, err = b.sessions.OpenInternal(req.HostLabel, req.ProjectRoot, ttl, req.AgentSafe, req.ConsumerName)
	} else {
		session, err = b.sessions.Open(req.HostLabel, req.ProjectRoot, ttl, req.AgentSafe, req.ConsumerName)
	}
	if err != nil {
		return err
	}
	*reply = OpenSessionResponse{
		SessionID:    session.ID,
		SessionToken: session.Token,
		LocalUser:    session.LocalUser,
		HostLabel:    session.HostLabel,
		ProjectRoot:  session.ProjectRoot,
		AgentSafe:    session.AgentSafe,
		ConsumerName: session.ConsumerName,
		Internal:     session.Internal,
		LastSeenAt:   session.LastSeenAt,
		ExpiresAt:    session.ExpiresAt,
	}
	b.appendAudit(audit.EventApprove, "daemon", map[string]any{
		"action":        "session.open",
		"host_label":    session.HostLabel,
		"project_root":  session.ProjectRoot,
		"agent_safe":    session.AgentSafe,
		"consumer_name": session.ConsumerName,
	})
	if b.events != nil {
		b.events.publish("vault.unlocked", fmt.Sprintf(`{"remaining_ttl":%d}`, int(time.Until(session.ExpiresAt).Seconds())))
		if !session.Internal {
			b.events.publish("leases.changed", leaseChangedEventPayload([]Session{session}, "active"))
			b.events.publish("access.changed", leaseChangedEventPayload([]Session{session}, "active"))
		}
		b.events.publish("dashboard.changed", `{"source":"session.open"}`)
	}
	return nil
}

func (b *brokerRPC) ResolveSession(req ResolveSessionRequest, reply *ResolveSessionResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	session, ok := b.sessions.Resolve(req.SessionToken)
	if !ok {
		return errors.New("session not found")
	}
	*reply = ResolveSessionResponse{Session: session.View()}
	return nil
}

func (b *brokerRPC) RevokeSession(req RevokeSessionRequest, reply *RevokeSessionResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	session, _ := b.sessions.Resolve(req.SessionToken)
	revoked := b.sessions.Revoke(req.SessionToken)
	*reply = RevokeSessionResponse{Revoked: revoked}
	if revoked {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "session.revoke", "session_id": session.ID})
		if b.events != nil {
			b.events.publish("leases.changed", leaseChangedEventPayload([]Session{session}, "revoked"))
			b.events.publish("access.changed", leaseChangedEventPayload([]Session{session}, "revoked"))
			b.events.publish("dashboard.changed", `{"source":"session.revoke"}`)
		}
	}
	return nil
}

func (b *brokerRPC) RevokeAllSessions(_ RevokeAllSessionsRequest, reply *RevokeAllSessionsResponse) error {
	revoked := b.sessions.RevokeAll()
	*reply = RevokeAllSessionsResponse{RevokedCount: len(revoked)}
	b.appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "session.revoke_all", "revoked_count": len(revoked)})
	if b.events != nil {
		b.events.publish("leases.changed", leaseChangedEventPayload(revoked, "revoked"))
		b.events.publish("access.changed", leaseChangedEventPayload(revoked, "revoked"))
		b.events.publish("dashboard.changed", `{"source":"session.revoke_all"}`)
	}
	return nil
}

func (b *brokerRPC) ListLeases(req ListLeasesRequest, reply *ListLeasesResponse) error {
	if b.sessions == nil {
		return errors.New("session store unavailable")
	}
	opts := leases.ListOptions{
		ConsumerID: strings.TrimSpace(req.ConsumerID),
		Status:     strings.TrimSpace(req.Status),
		Cursor:     strings.TrimSpace(req.Cursor),
		Limit:      req.Limit,
		Now:        time.Now().UTC(),
	}
	if req.ExpiringInSeconds > 0 {
		opts.ExpiringIn = time.Duration(req.ExpiringInSeconds) * time.Second
	}
	*reply = leases.List(b.sessions.LeaseSnapshot(), opts)
	return nil
}

func (b *brokerRPC) AccessMatrix(req AccessMatrixRequest, reply *AccessMatrixResponse) error {
	if b.matrixInput == nil {
		b.matrixInput = defaultAccessMatrixInput
	}
	input, err := b.matrixInput(context.Background(), b.paths, b.sessions)
	if err != nil {
		return err
	}
	if b.approvals != nil {
		input.Approvals = b.approvals.Snapshot()
	}
	if b.audit != nil {
		if events, err := b.audit.Events(); err == nil {
			input.AuditEvents = events
		}
	}
	out, err := accessmatrix.Build(input, accessmatrix.Options{
		Range:          strings.TrimSpace(req.Range),
		Consumer:       strings.TrimSpace(req.Consumer),
		Secret:         strings.TrimSpace(req.Secret),
		Scope:          strings.TrimSpace(req.Scope),
		Source:         strings.TrimSpace(req.Source),
		HasActiveLease: req.HasActiveLease,
		Cursor:         strings.TrimSpace(req.Cursor),
		Limit:          req.Limit,
	})
	if err != nil {
		return err
	}
	*reply = out
	return nil
}

func (b *brokerRPC) Policy(_ PolicyGetRequest, reply *PolicyResponse) error {
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return err
	}
	*reply = policyResponseFromDocument(handle.GetPolicy())
	return nil
}

func (b *brokerRPC) SetPolicy(req PolicySetRequest, reply *PolicyResponse) error {
	if req.ValidateOnly {
		if err := store.ValidatePolicy(req.Policy); err != nil {
			return err
		}
		if req.ReturnValidated {
			doc := req.Policy
			doc.Version = ""
			doc.UpdatedBy = ""
			doc.UpdatedAt = time.Time{}
			*reply = policyResponseFromDocument(doc)
		}
		return nil
	}
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return err
	}
	updated, err := handle.ReplacePolicy(req.Policy, strings.TrimSpace(req.IfMatch), req.Force, req.UpdatedBy)
	if err != nil {
		return err
	}
	*reply = policyResponseFromDocument(updated)
	if b.events != nil {
		b.events.publish("policy.changed", fmt.Sprintf(`{"version":%q}`, updated.Version))
		b.events.publish("dashboard.changed", `{"source":"policy.update"}`)
	}
	return nil
}

func policyResponseFromDocument(doc store.PolicyDocument) PolicyResponse {
	return PolicyResponse{Schema: jsonwire.SchemaVersion, PolicyDocument: doc}
}

func (b *brokerRPC) Config(_ ConfigGetRequest, reply *ConfigResponse) error {
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return err
	}
	*reply = ConfigResponse{Schema: jsonwire.SchemaVersion, Config: handle.GetConfig()}
	return nil
}

func (b *brokerRPC) SetConfig(req ConfigSetRequest, reply *ConfigValueResponse) error {
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return err
	}
	if _, err := handle.SetConfigValue(req.Key, req.Value, req.Actor); err != nil {
		return err
	}
	value, err := handle.GetConfigValue(req.Key)
	if err != nil {
		return err
	}
	*reply = ConfigValueResponse{Schema: jsonwire.SchemaVersion, Key: strings.TrimSpace(req.Key), Value: value}
	if b.events != nil {
		b.events.publish("config.changed", fmt.Sprintf(`{"key":%q}`, strings.TrimSpace(req.Key)))
		b.events.publish("dashboard.changed", `{"source":"config.update"}`)
	}
	return nil
}

func (b *brokerRPC) Backup(req BackupRequest, reply *BackupResponse) error {
	outputPath := strings.TrimSpace(req.DestinationPath)
	if outputPath == "" {
		return errors.New("destination_path is required")
	}
	if filepath.Ext(outputPath) != ".hasp-backup" {
		outputPath += ".hasp-backup"
	}
	passphrase := req.Passphrase
	if strings.TrimSpace(passphrase) == "" {
		return errors.New("passphrase is required")
	}
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return err
	}
	checkpoint, err := handle.ExportBackup(context.Background(), outputPath, passphrase)
	if err != nil {
		return err
	}
	signatureStatus, err := store.BackupSignatureStatusForFile(outputPath)
	if err != nil {
		return err
	}
	config := handle.GetConfig()
	retention := 5
	if raw, ok := config["backup.retention_count"].(int); ok && raw > 0 {
		retention = raw
	}
	if err := store.PruneBackupDirectory(filepath.Dir(outputPath), retention, handle.BackupVaultID()); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = handle.SetConfigValue("backup.last_backup_at", now, "http")
	_, _ = handle.SetConfigValue("backup.last_backup_path", outputPath, "http")
	*reply = BackupResponse{
		Schema:     jsonwire.SchemaVersion,
		Path:       outputPath,
		Checkpoint: checkpoint,
		Pruned:     true,
		Signature:  signatureStatus,
	}
	if b.events != nil {
		b.events.publish("backup.created", fmt.Sprintf(`{"path":%q}`, outputPath))
		b.events.publish("config.changed", `{"key":"backup.last_backup_at"}`)
		b.events.publish("dashboard.changed", `{"source":"backup.export"}`)
	}
	return nil
}

func (b *brokerRPC) BackupPassphraseStatus() BackupPassphraseStatusResponse {
	_, err := b.backupPassphraseFromKeyring()
	if err == nil {
		return BackupPassphraseStatusResponse{Schema: jsonwire.SchemaVersion, Enrolled: true, Available: true, Source: "keychain"}
	}
	return BackupPassphraseStatusResponse{Schema: jsonwire.SchemaVersion, Enrolled: false, Available: !errors.Is(err, store.ErrKeyringUnavailable)}
}

func (b *brokerRPC) SetBackupPassphrase(req BackupPassphraseRequest) (BackupPassphraseStatusResponse, error) {
	if strings.TrimSpace(req.Passphrase) == "" {
		return BackupPassphraseStatusResponse{}, errors.New("passphrase is required")
	}
	if err := b.keyring.Set(context.Background(), backupPassphraseSvc, backupPassphraseAccount(), req.Passphrase); err != nil {
		return BackupPassphraseStatusResponse{}, err
	}
	b.appendBackupPassphraseAudit("backup.passphrase.enroll")
	return BackupPassphraseStatusResponse{Schema: jsonwire.SchemaVersion, Enrolled: true, Available: true, Source: "keychain"}, nil
}

func (b *brokerRPC) DeleteBackupPassphrase() (BackupPassphraseStatusResponse, error) {
	if err := b.keyring.Delete(backupPassphraseSvc, backupPassphraseAccount()); err != nil && !store.IsKeyringItemNotFound(err) {
		return BackupPassphraseStatusResponse{}, err
	}
	b.appendBackupPassphraseAudit("backup.passphrase.remove")
	return BackupPassphraseStatusResponse{Schema: jsonwire.SchemaVersion, Enrolled: false, Available: true}, nil
}

func (b *brokerRPC) backupPassphraseFromKeyring() (string, error) {
	passphrase, err := b.keyring.Get(backupPassphraseSvc, backupPassphraseAccount())
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(passphrase) == "" {
		return "", store.ErrKeyringUnavailable
	}
	return passphrase, nil
}

func (b *brokerRPC) appendBackupPassphraseAudit(action string) {
	if b.audit == nil {
		return
	}
	_, _ = b.audit.Append(audit.EventOverride, "user", map[string]any{"action": action, "custody": "keychain"})
}

func backupPassphraseAccount() string {
	for _, value := range []string{os.Getenv("USER"), os.Getenv("LOGNAME"), os.Getenv("USERNAME")} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return "default"
}

func (b *brokerRPC) runScheduledBackups(ctx context.Context) {
	ticker := time.NewTicker(backupSchedulerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_ = b.runScheduledBackupOnce(ctx, now.UTC())
		}
	}
}

func (b *brokerRPC) runScheduledBackupOnce(ctx context.Context, now time.Time) error {
	passphrase := os.Getenv("HASP_BACKUP_PASSPHRASE")
	if strings.TrimSpace(passphrase) == "" {
		var err error
		passphrase, err = b.backupPassphraseFromKeyring()
		if err != nil {
			return nil
		}
	}
	handle, err := openRuntimeVaultHandle(ctx, b.paths)
	if err != nil {
		return err
	}
	config := handle.GetConfig()
	schedule, _ := config["backup.schedule"].(string)
	if schedule == "" || schedule == "off" {
		return nil
	}
	lastRaw, _ := config["backup.last_backup_at"].(string)
	if !backupScheduleDue(schedule, lastRaw, now) {
		return nil
	}
	destination, _ := config["backup.destination_path"].(string)
	outputPath := scheduledBackupPath(destination, now)
	if outputPath == "" {
		return nil
	}
	var reply BackupResponse
	return b.Backup(BackupRequest{DestinationPath: outputPath, Passphrase: passphrase}, &reply)
}

func backupScheduleDue(schedule string, lastRaw string, now time.Time) bool {
	schedule = strings.TrimSpace(schedule)
	if schedule == "" || schedule == "off" {
		return false
	}
	lastRaw = strings.TrimSpace(lastRaw)
	if lastRaw == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, lastRaw)
	if err != nil {
		return true
	}
	switch schedule {
	case "daily":
		return !last.After(now) && now.Sub(last) >= 24*time.Hour
	case "weekly":
		return !last.After(now) && now.Sub(last) >= 7*24*time.Hour
	default:
		return false
	}
}

func scheduledBackupPath(destination string, now time.Time) string {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return ""
	}
	filename := fmt.Sprintf("HASP-%s.hasp-backup", now.UTC().Format("20060102-150405"))
	if strings.HasSuffix(destination, string(os.PathSeparator)) {
		return filepath.Join(destination, filename)
	}
	if filepath.Ext(destination) == ".hasp-backup" {
		return filepath.Join(filepath.Dir(destination), filename)
	}
	return filepath.Join(destination, filename)
}

func (b *brokerRPC) Integrations(_ IntegrationGetRequest, reply *IntegrationListResponse) error {
	out, err := integrations.List(b.integrationOptions())
	if err != nil {
		return err
	}
	out.Integrations = filterDisabledIntegrations(out.Integrations, b.disabledIntegrationTargets())
	*reply = out
	return nil
}

func (b *brokerRPC) IntegrationProfileCatalog(_ IntegrationGetRequest, reply *IntegrationProfilesResponse) error {
	out, err := integrations.ProfileCatalog(b.integrationOptions())
	if err != nil {
		return err
	}
	disabled := b.disabledIntegrationTargets()
	if len(disabled) > 0 {
		filtered := out.Profiles[:0]
		for _, profile := range out.Profiles {
			if !disabled[strings.TrimSpace(profile.TargetID)] {
				filtered = append(filtered, profile)
			}
		}
		out.Profiles = filtered
	}
	*reply = out
	return nil
}

func (b *brokerRPC) IntegrationProfiles(req IntegrationProfilesRequest, reply *IntegrationProfilesResponse) error {
	if b.disabledIntegrationTargets()[strings.TrimSpace(req.TargetID)] {
		return fmt.Errorf("%w: %s", integrations.ErrTargetNotFound, req.TargetID)
	}
	out, err := integrations.Profiles(req.TargetID, b.integrationOptions())
	if err != nil {
		return err
	}
	*reply = out
	return nil
}

func (b *brokerRPC) DoctorIntegration(req IntegrationDoctorRPCRequest, reply *IntegrationDoctorResponse) error {
	if b.disabledIntegrationTargets()[strings.TrimSpace(req.TargetID)] {
		return fmt.Errorf("%w: %s", integrations.ErrTargetNotFound, req.TargetID)
	}
	out, err := integrations.Doctor(req.TargetID, integrations.DoctorRequest{ProfileID: req.ProfileID}, b.integrationOptions())
	if err != nil {
		return err
	}
	*reply = out
	if b.events != nil {
		b.events.publish("integrations.changed", integrationChangedPayload(strings.TrimSpace(req.TargetID), statusFromIntegrationDoctor(out)))
		b.events.publish("dashboard.changed", `{"source":"integration.doctor"}`)
	}
	return nil
}

func (b *brokerRPC) CreateIntegrationProfile(req IntegrationProfileMutationRPCRequest, reply *IntegrationProfileMutationResponse) error {
	if b.disabledIntegrationTargets()[strings.TrimSpace(req.Body.TargetID)] {
		return fmt.Errorf("%w: %s", integrations.ErrTargetNotFound, req.Body.TargetID)
	}
	out, err := integrations.CreateProfile(req.Body, b.integrationOptions())
	if err != nil {
		return err
	}
	*reply = out
	b.recordIntegrationProfileMutation(audit.EventApprove, "integration.profile.create", out.Profile)
	return nil
}

func (b *brokerRPC) UpdateIntegrationProfile(req IntegrationProfileMutationRPCRequest, reply *IntegrationProfileMutationResponse) error {
	if b.disabledIntegrationTargets()[strings.TrimSpace(req.TargetID)] {
		return fmt.Errorf("%w: %s", integrations.ErrTargetNotFound, req.TargetID)
	}
	out, err := integrations.UpdateProfile(req.TargetID, req.ProfileID, req.Body, req.IfMatch, b.integrationOptions())
	if err != nil {
		return err
	}
	*reply = out
	b.recordIntegrationProfileMutation(audit.EventOverride, "integration.profile.update", out.Profile)
	return nil
}

func (b *brokerRPC) DeleteIntegrationProfile(req IntegrationProfileMutationRPCRequest, reply *IntegrationProfileMutationResponse) error {
	if b.disabledIntegrationTargets()[strings.TrimSpace(req.TargetID)] {
		return fmt.Errorf("%w: %s", integrations.ErrTargetNotFound, req.TargetID)
	}
	out, err := integrations.DeleteProfile(req.TargetID, req.ProfileID, req.IfMatch, b.integrationOptions())
	if err != nil {
		return err
	}
	*reply = out
	b.recordIntegrationProfileMutation(audit.EventOverride, "integration.profile.delete", out.Profile)
	return nil
}

func (b *brokerRPC) integrationOptions() integrations.Options {
	return integrations.Options{
		SchemaVersion:      jsonwire.SchemaVersion,
		ProfileCatalogPath: integrationProfileCatalogPath(b.paths),
	}
}

func integrationProfileCatalogPath(runtimePaths paths.Paths) string {
	if strings.TrimSpace(runtimePaths.HomeDir) == "" {
		return ""
	}
	return filepath.Join(runtimePaths.HomeDir, "integrations.profiles.json")
}

func (b *brokerRPC) recordIntegrationProfileMutation(eventType string, action string, profile IntegrationProfile) {
	details := map[string]any{
		"action":     action,
		"target_id":  profile.TargetID,
		"profile_id": profile.ID,
	}
	_, err := audit.NewForPaths(b.paths).Append(eventType, "daemon", details)
	if b.auditState != nil {
		b.auditState.RecordAppendResult(err)
	}
	if b.events != nil {
		payload := integrationProfileChangedPayload(profile.TargetID, profile.ID, strings.TrimPrefix(action, "integration.profile."))
		b.events.publish("integrations.profiles.changed", payload)
		b.events.publish("integrations.changed", integrationChangedPayload(profile.TargetID, "ok"))
		b.events.publish("dashboard.changed", `{"source":"integration.profile"}`)
	}
}

func (b *brokerRPC) disabledIntegrationTargets() map[string]bool {
	handle, err := openRuntimeVaultHandle(context.Background(), b.paths)
	if err != nil {
		return map[string]bool{}
	}
	disabled := make(map[string]bool)
	value, err := handle.GetConfigValue("integrations.disabled_targets")
	if err != nil {
		return disabled
	}
	for _, target := range configStringSlice(value) {
		disabled[target] = true
	}
	return disabled
}

func filterDisabledIntegrations(input []Integration, disabled map[string]bool) []Integration {
	if len(disabled) == 0 {
		return input
	}
	filtered := input[:0]
	for _, integration := range input {
		if !disabled[integration.ID] {
			filtered = append(filtered, integration)
		}
	}
	return filtered
}

func configStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func integrationChangedPayload(id string, status string) string {
	data, err := json.Marshal(map[string]string{"id": id, "status": status})
	if err != nil {
		return `{"id":"","status":"degraded"}`
	}
	return string(data)
}

func integrationProfileChangedPayload(targetID string, profileID string, action string) string {
	data, err := json.Marshal(struct {
		TargetID  string `json:"target_id"`
		ProfileID string `json:"profile_id"`
		Action    string `json:"action"`
	}{TargetID: targetID, ProfileID: profileID, Action: action})
	if err != nil {
		return `{"target_id":"","profile_id":"","action":"changed"}`
	}
	return string(data)
}

func statusFromIntegrationDoctor(reply IntegrationDoctorResponse) string {
	if !reply.RuntimeProbe {
		return "metadata_only"
	}
	if reply.OK {
		return "ok"
	}
	return "degraded"
}

func (b *brokerRPC) RevokeLease(req RevokeLeaseRequest, reply *RevokeLeaseResponse) error {
	if b.sessions == nil {
		return errors.New("session store unavailable")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "operator"
	}
	leaseIDs := uniqueNonEmptyStrings(req.LeaseIDs)
	if len(leaseIDs) > 0 {
		revokedSessions := make([]Session, 0, len(leaseIDs))
		for _, leaseID := range leaseIDs {
			session, found, changed := b.sessions.RevokeLeaseID(leaseID)
			if !found {
				continue
			}
			if changed {
				revokedSessions = append(revokedSessions, session)
				b.appendAudit(audit.EventDeny, "daemon", map[string]any{
					"action":      "lease.revoke",
					"lease_id":    session.ID,
					"consumer_id": sessionConsumerID(session),
					"reason":      reason,
					"bulk":        true,
				})
			}
		}
		*reply = RevokeLeaseResponse{Revoked: len(revokedSessions) > 0, RevokedCount: len(revokedSessions)}
		if b.events != nil && len(revokedSessions) > 0 {
			b.events.publish("leases.changed", leaseChangedEventPayload(revokedSessions, "revoked"))
			b.events.publish("access.changed", leaseChangedEventPayload(revokedSessions, "revoked"))
			b.events.publish("dashboard.changed", `{"source":"lease.bulk_revoke"}`)
		}
		return nil
	}
	if consumer := strings.TrimSpace(req.AllForConsumer); consumer != "" {
		revoked := b.sessions.RevokeAllForConsumer(consumer)
		*reply = RevokeLeaseResponse{Revoked: len(revoked) > 0, RevokedCount: len(revoked)}
		for _, session := range revoked {
			b.appendAudit(audit.EventDeny, "daemon", map[string]any{
				"action":      "lease.revoke",
				"lease_id":    session.ID,
				"consumer_id": sessionConsumerID(session),
				"reason":      reason,
				"bulk":        true,
			})
		}
		if b.events != nil {
			b.events.publish("leases.changed", leaseChangedEventPayload(revoked, "revoked"))
			b.events.publish("access.changed", leaseChangedEventPayload(revoked, "revoked"))
			b.events.publish("dashboard.changed", `{"source":"lease.bulk_revoke"}`)
		}
		return nil
	}
	leaseID := strings.TrimSpace(req.LeaseID)
	if leaseID == "" {
		return errors.New("lease_id is required")
	}
	session, found, changed := b.sessions.RevokeLeaseID(leaseID)
	*reply = RevokeLeaseResponse{Revoked: found, RevokedCount: 0}
	if changed {
		reply.RevokedCount = 1
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action":      "lease.revoke",
			"lease_id":    session.ID,
			"consumer_id": sessionConsumerID(session),
			"reason":      reason,
		})
		if b.events != nil {
			b.events.publish("leases.changed", leaseChangedEventPayload([]Session{session}, "revoked"))
			b.events.publish("access.changed", leaseChangedEventPayload([]Session{session}, "revoked"))
			b.events.publish("dashboard.changed", `{"source":"lease.revoke"}`)
		}
	}
	return nil
}

func uniqueNonEmptyStrings(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func leaseChangedEventPayload(sessions []Session, status string) string {
	leaseIDs := make([]string, 0, len(sessions))
	leaseViews := make([]leases.Lease, 0, len(sessions))
	for _, session := range sessions {
		if session.ID == "" || session.Internal {
			continue
		}
		leaseIDs = append(leaseIDs, session.ID)
		view := sessionLeaseView(session)
		if status != "" {
			view.Status = status
		}
		leaseViews = append(leaseViews, view)
	}
	payload := map[string]any{
		"lease_ids":     leaseIDs,
		"leases":        leaseViews,
		"status":        status,
		"revoked_count": len(leaseViews),
	}
	if len(leaseIDs) == 1 {
		payload["lease_id"] = leaseIDs[0]
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"lease_ids":[],"status":%q}`, status)
	}
	return string(data)
}

func sessionLeaseView(session Session) leases.Lease {
	status := "active"
	if session.RevokedAt != nil {
		status = session.LeaseStatus
		if status == "" {
			status = "revoked"
		}
	}
	return leases.Lease{
		ID:         session.ID,
		SecretID:   sessionSecretID(session),
		ConsumerID: sessionConsumerID(session),
		GrantedAt:  session.OpenedAt,
		ExpiresAt:  session.ExpiresAt,
		LastUsedAt: session.LastSeenAt,
		Scope:      sessionScope(session),
		Status:     status,
	}
}

func (b *brokerRPC) ListApprovals(req ListApprovalsRequest, reply *ListApprovalsResponse) error {
	if b.approvals == nil {
		return errors.New("approval store unavailable")
	}
	*reply = approvals.List(b.approvals.Snapshot(), approvals.ListOptions{
		Status:     strings.TrimSpace(req.Status),
		ConsumerID: strings.TrimSpace(req.ConsumerID),
		Now:        time.Now().UTC(),
	})
	return nil
}

func (b *brokerRPC) DecideApproval(req DecideApprovalRequest, reply *DecideApprovalResponse) error {
	if b.approvals == nil {
		return errors.New("approval store unavailable")
	}
	decisionText := strings.TrimSpace(req.Decision)
	grant := false
	switch decisionText {
	case "grant":
		grant = true
		if strings.TrimSpace(req.Reason) != "" {
			return errors.New("reason is only valid for deny decisions")
		}
		if req.HoldDurationMS < 1500 {
			return errors.New("approval grant requires a 1.5s hold proof")
		}
		authMethod := strings.TrimSpace(req.AuthMethod)
		if authMethod != "touch-id" && authMethod != "device-owner" {
			return errors.New("approval grant requires touch-id or device-owner auth")
		}
	case "deny":
		if req.GrantedTTLS != 0 || strings.TrimSpace(req.Scope) != "" {
			return errors.New("ttl and scope are only valid for grant decisions")
		}
	default:
		return errors.New(`decision must be "grant" or "deny"`)
	}
	decision := approvals.Decision{
		GrantedTTLS: req.GrantedTTLS,
		Scope:       strings.TrimSpace(req.Scope),
		Reason:      strings.TrimSpace(req.Reason),
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		actor = "cli"
	}
	pendingApproval, err := b.approvals.PrepareDecision(req.ApprovalID)
	if err != nil {
		return err
	}
	var grantedSession Session
	var leaseID string
	var preparedLease Session
	if grant && pendingApproval.Status == "pending" {
		ttl := time.Duration(req.GrantedTTLS) * time.Second
		if ttl <= 0 {
			ttl = time.Duration(pendingApproval.RequestedTTLS) * time.Second
		}
		if ttl <= 0 || ttl > DefaultSessionTTL {
			ttl = DefaultSessionTTL
		}
		scope := strings.TrimSpace(req.Scope)
		if scope == "" {
			scope = pendingApproval.RequestedScope
		}
		session, err := b.sessions.newSession("approval:"+pendingApproval.RequesterConsumerID, "", ttl, false, pendingApproval.RequesterConsumerID)
		if err != nil {
			return err
		}
		session.LeaseSecretID = strings.TrimSpace(pendingApproval.SecretID)
		session.LeaseScope = strings.TrimSpace(scope)
		if session.LeaseScope == "" {
			session.LeaseScope = "session"
		}
		preparedLease = session
		leaseID = session.ID
		decision.GrantedTTLS = int(ttl.Seconds())
		decision.Scope = session.LeaseScope
	}
	var approval approvals.Approval
	var changed bool
	if leaseID != "" {
		b.sessions.mu.Lock()
		if b.sessions.locked || b.sessions.activeCountLocked(b.sessions.now().UTC()) == 0 {
			err = errVaultLocked
			leaseID = ""
		} else {
			approval, changed, err = b.approvals.DecidePrepared(req.ApprovalID, &decision, actor, grant)
		}
		if err == nil && changed {
			b.sessions.sessions[preparedLease.Token] = preparedLease
			grantedSession = preparedLease
		} else {
			leaseID = ""
		}
		b.sessions.mu.Unlock()
	} else {
		approval, changed, err = b.approvals.DecidePrepared(req.ApprovalID, &decision, actor, grant)
	}
	if err != nil {
		return err
	}
	response := DecideApprovalResponse{Approval: approval, Changed: changed}
	if changed {
		details := map[string]any{
			"action":      "approval.decide",
			"approval_id": approval.ID,
			"decision":    decisionText,
			"secret_id":   approval.SecretID,
			"consumer_id": approval.RequesterConsumerID,
		}
		if decision.Reason != "" {
			details["reason"] = decision.Reason
		}
		if grant {
			response.LeaseID = leaseID
			details["lease_id"] = leaseID
			details["granted_ttl_s"] = decision.GrantedTTLS
			details["auth_method"] = strings.TrimSpace(req.AuthMethod)
			details["hold_duration_ms"] = req.HoldDurationMS
		}
		eventType := audit.EventApprove
		if !grant {
			eventType = audit.EventDeny
		}
		b.appendAudit(eventType, "daemon", details)
		if b.events != nil {
			b.events.publish("approvals.changed", fmt.Sprintf(`{"approval_id":%q,"status":%q}`, approval.ID, approval.Status))
			if response.LeaseID != "" {
				b.events.publish("leases.changed", leaseChangedEventPayload([]Session{grantedSession}, "active"))
				b.events.publish("access.changed", leaseChangedEventPayload([]Session{grantedSession}, "active"))
			}
			b.events.publish("dashboard.changed", `{"source":"approval.decide"}`)
		}
	}
	*reply = response
	return nil
}

func (b *brokerRPC) LockVault(req LockVaultRequest, reply *LockVaultResponse) error {
	revoked := b.sessions.RevokeAll()
	*reply = LockVaultResponse{RevokedCount: len(revoked), Locked: true}
	details := map[string]any{"action": "vault.lock", "revoked_count": len(revoked)}
	if strings.TrimSpace(req.Cause) != "" {
		details["cause"] = strings.TrimSpace(req.Cause)
	}
	b.appendAudit(audit.EventDeny, "daemon", details)
	cause := strings.TrimSpace(req.Cause)
	if cause == "" {
		cause = "manual"
	}
	if b.events != nil {
		b.events.publish("vault.locked", fmt.Sprintf(`{"cause":%q}`, cause))
		b.events.publish("leases.changed", leaseChangedEventPayload(revoked, "revoked"))
		b.events.publish("access.changed", leaseChangedEventPayload(revoked, "revoked"))
		b.events.publish("dashboard.changed", `{"source":"vault.lock"}`)
	}
	return nil
}

func (b *brokerRPC) RegisterProcess(req RegisterProcessRequest, reply *RegisterProcessResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	if req.PID <= 0 {
		return errors.New("pid is required")
	}
	// Socket peer-PID validation: the kernel-attested socket peer must be
	// either req.PID itself (self-registration) OR an ancestor of req.PID
	// (parent registering a child it spawned — `hasp agent launch` flow).
	// Same-uid file permissions alone don't stop a neighbouring process from
	// binding a session to an arbitrary target PID; the lineage gate does.
	// peerPID == 0 means "unknown" (lookup failed or brokerRPC isn't bound to
	// a connection); fail closed.
	if b.peerPID == 0 {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action": "session.process.register.reject",
			"reason": "unknown_peer_pid",
			"pid":    req.PID,
		})
		return errors.New("peer pid unavailable; refusing to bind session to caller-supplied pid")
	}
	if !peerSharesLineage(b.peerPID, req.PID) {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action":   "session.process.register.reject",
			"reason":   "peer_not_in_lineage",
			"req_pid":  req.PID,
			"peer_pid": b.peerPID,
		})
		return fmt.Errorf("pid lineage mismatch: socket peer PID=%d shares no lineage with req.PID=%d", b.peerPID, req.PID)
	}
	registered := b.sessions.RegisterProcess(req.SessionToken, req.PID)
	*reply = RegisterProcessResponse{Registered: registered}
	if !registered {
		return errors.New("session not found")
	}
	b.appendAudit(audit.EventApprove, "daemon", map[string]any{"action": "session.process.register", "pid": req.PID})
	return nil
}

// peerSharesLineage reports whether the kernel-attested socket peer is allowed
// to bind a session to reqPID. Self (peerPID == reqPID) and peer-as-ancestor of
// reqPID (parent registering a child it spawned) are valid trust paths. The
// reverse path is intentionally denied: a child must not register its parent,
// because that would grant the session to sibling processes under that parent.
func peerSharesLineage(peerPID uint32, reqPID int) bool {
	if peerPID == 0 || reqPID <= 0 {
		return false
	}
	if uint32(reqPID) == peerPID {
		return true
	}
	if reqLineage, err := processLineage(reqPID); err == nil {
		for _, ancestor := range reqLineage {
			if uint32(ancestor) == peerPID {
				return true
			}
		}
	}
	return false
}

func (b *brokerRPC) appendAudit(eventType string, actor string, details map[string]any) {
	if b.audit == nil {
		b.auditState.RecordAppendResult(errors.New("audit logger unavailable"))
		return
	}
	_, err := b.audit.Append(eventType, actor, details)
	b.auditState.RecordAppendResult(err)
	if err == nil && b.events != nil {
		b.events.publish("audit.changed", fmt.Sprintf(`{"type":%q}`, eventType))
	}
}

func (b *brokerRPC) ResolveProcess(req ResolveProcessRequest, reply *ResolveProcessResponse) error {
	if req.PID <= 0 {
		return errors.New("pid is required")
	}
	session, token, ok := b.sessions.ResolveProcess(req.PID)
	if !ok {
		*reply = ResolveProcessResponse{Found: false}
		return nil
	}
	*reply = ResolveProcessResponse{
		Found:        true,
		SessionToken: token,
		Session:      session.View(),
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket file at %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}
