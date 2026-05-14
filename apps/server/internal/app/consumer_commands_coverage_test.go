package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type consumerCommandRPC struct {
	accessReq   runtime.AccessMatrixRequest
	accessReply runtime.AccessMatrixResponse
	accessErr   error

	leaseListReq   runtime.ListLeasesRequest
	leaseListReply runtime.ListLeasesResponse
	leaseListErr   error

	revokeReq   runtime.RevokeLeaseRequest
	revokeReply runtime.RevokeLeaseResponse
	revokeErr   error

	approvalListReq   runtime.ListApprovalsRequest
	approvalListReply runtime.ListApprovalsResponse
	approvalListErr   error

	decideReq   runtime.DecideApprovalRequest
	decideReply runtime.DecideApprovalResponse
	decideErr   error

	configReply    runtime.ConfigResponse
	configErr      error
	setConfigReq   runtime.ConfigSetRequest
	setConfigReply runtime.ConfigValueResponse
	setConfigErr   error

	policyReply    runtime.PolicyResponse
	policyErr      error
	setPolicyReq   runtime.PolicySetRequest
	setPolicyReply runtime.PolicyResponse
	setPolicyErr   error
}

func (r *consumerCommandRPC) AccessMatrix(req runtime.AccessMatrixRequest, reply *runtime.AccessMatrixResponse) error {
	r.accessReq = req
	if r.accessErr != nil {
		return r.accessErr
	}
	*reply = r.accessReply
	return nil
}

func (r *consumerCommandRPC) ListLeases(req runtime.ListLeasesRequest, reply *runtime.ListLeasesResponse) error {
	r.leaseListReq = req
	if r.leaseListErr != nil {
		return r.leaseListErr
	}
	*reply = r.leaseListReply
	return nil
}

func (r *consumerCommandRPC) RevokeLease(req runtime.RevokeLeaseRequest, reply *runtime.RevokeLeaseResponse) error {
	r.revokeReq = req
	if r.revokeErr != nil {
		return r.revokeErr
	}
	*reply = r.revokeReply
	return nil
}

func (r *consumerCommandRPC) ListApprovals(req runtime.ListApprovalsRequest, reply *runtime.ListApprovalsResponse) error {
	r.approvalListReq = req
	if r.approvalListErr != nil {
		return r.approvalListErr
	}
	*reply = r.approvalListReply
	return nil
}

func (r *consumerCommandRPC) DecideApproval(req runtime.DecideApprovalRequest, reply *runtime.DecideApprovalResponse) error {
	r.decideReq = req
	if r.decideErr != nil {
		return r.decideErr
	}
	*reply = r.decideReply
	return nil
}

func (r *consumerCommandRPC) Config(_ runtime.ConfigGetRequest, reply *runtime.ConfigResponse) error {
	if r.configErr != nil {
		return r.configErr
	}
	*reply = r.configReply
	return nil
}

func (r *consumerCommandRPC) SetConfig(req runtime.ConfigSetRequest, reply *runtime.ConfigValueResponse) error {
	r.setConfigReq = req
	if r.setConfigErr != nil {
		return r.setConfigErr
	}
	*reply = r.setConfigReply
	return nil
}

func (r *consumerCommandRPC) Policy(_ runtime.PolicyGetRequest, reply *runtime.PolicyResponse) error {
	if r.policyErr != nil {
		return r.policyErr
	}
	*reply = r.policyReply
	return nil
}

func (r *consumerCommandRPC) SetPolicy(req runtime.PolicySetRequest, reply *runtime.PolicyResponse) error {
	r.setPolicyReq = req
	if r.setPolicyErr != nil {
		return r.setPolicyErr
	}
	*reply = r.setPolicyReply
	return nil
}

type consumerCommandStarter struct {
	socketPath string
	ensureErr  error
	connectErr error
}

func (s consumerCommandStarter) EnsureDaemon(context.Context) error {
	return s.ensureErr
}

func (s consumerCommandStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	if s.connectErr != nil {
		return nil, s.connectErr
	}
	return runtime.Dial(ctx, s.socketPath)
}

func startConsumerCommandRPC(t *testing.T, service *consumerCommandRPC) consumerCommandStarter {
	t.Helper()
	socketPath := shortSocketPath(t, "consumer-command.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen consumer command rpc: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register consumer command rpc: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return consumerCommandStarter{socketPath: socketPath}
}

func TestAccessConsumerCommandRemainingBranches(t *testing.T) {
	lockAppSeams(t)
	service := &consumerCommandRPC{
		accessReply: runtime.AccessMatrixResponse{Grants: []runtime.AccessMatrixGrant{{
			ConsumerID: "agent", SecretID: "secret", Scope: "window", Source: "manual", LeaseCount: 1, LastUsedAt: "2026-05-14T00:00:00Z",
		}}},
	}
	starter := startConsumerCommandRPC(t, service)

	var out bytes.Buffer
	if err := accessCommand(context.Background(), nil, errWriter{err: errors.New("help fail")}, starter); err == nil {
		t.Fatal("expected access help writer failure")
	}
	if err := accessCommand(context.Background(), []string{"bad"}, &out, starter); err == nil {
		t.Fatal("expected unknown access subcommand")
	}
	if err := accessMatrixCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected access matrix parse error")
	}
	if err := accessMatrixCommand(context.Background(), []string{"extra"}, &out, starter); err == nil {
		t.Fatal("expected access matrix usage error")
	}
	if err := accessMatrixCommand(context.Background(), []string{"--has-active-lease", "maybe"}, &out, starter); err == nil {
		t.Fatal("expected access matrix invalid has-active-lease")
	}
	if err := accessMatrixCommand(context.Background(), []string{"--has-active-lease", "true"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected access matrix ensure error")
	}
	service.accessErr = errors.New("matrix rpc fail")
	if err := accessMatrixCommand(context.Background(), []string{"--has-active-lease", "false"}, &out, starter); err == nil {
		t.Fatal("expected access matrix rpc error")
	}
	service.accessErr = nil
	if err := accessMatrixCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--consumer", "agent", "--secret", "secret", "--scope", "window", "--source", "manual", "--cursor", "2", "--limit", "7", "--has-active-lease", "TRUE"}, errWriter{err: errors.New("json fail")}, starter); err == nil {
		t.Fatal("expected access matrix json write error")
	}
	if service.accessReq.Consumer != "agent" || service.accessReq.Cursor != "2" || service.accessReq.Limit != 7 || service.accessReq.HasActiveLease == nil || !*service.accessReq.HasActiveLease {
		t.Fatalf("access request = %+v", service.accessReq)
	}
	out.Reset()
	if err := renderAccessMatrix(&out, nil); err != nil {
		t.Fatalf("render empty access matrix: %v", err)
	}
	if !strings.Contains(out.String(), "No access grants.") {
		t.Fatalf("empty access matrix output = %q", out.String())
	}
	if err := renderAccessMatrix(errWriter{err: errors.New("access render fail")}, service.accessReply.Grants); err == nil {
		t.Fatal("expected access table write failure")
	}
}

func TestLeaseConsumerCommandRemainingBranches(t *testing.T) {
	lockAppSeams(t)
	now := time.Date(2026, 5, 14, 1, 2, 3, 0, time.UTC)
	service := &consumerCommandRPC{
		leaseListReply: runtime.ListLeasesResponse{Leases: []runtime.Lease{{
			ID: "lease-1", SecretID: "secret", ConsumerID: "agent", Scope: "window", Status: "active", LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
		}}},
		revokeReply: runtime.RevokeLeaseResponse{Revoked: true, RevokedCount: 1},
	}
	starter := startConsumerCommandRPC(t, service)
	var out bytes.Buffer

	if err := leaseCommand(context.Background(), nil, errWriter{err: errors.New("help fail")}, starter); err == nil {
		t.Fatal("expected lease help writer failure")
	}
	if err := leaseListCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected lease list parse error")
	}
	if err := leaseListCommand(context.Background(), []string{"--consumer", "agent", "--status", "active", "--expiring-in", "2m", "--cursor", "next", "--limit", "3"}, errWriter{err: errors.New("lease json fail")}, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected lease list ensure error")
	}
	service.leaseListErr = errors.New("list fail")
	if err := leaseListCommand(context.Background(), []string{"--expiring-in", "2m"}, &out, starter); err == nil {
		t.Fatal("expected lease list rpc error")
	}
	service.leaseListErr = nil
	if err := leaseListCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--consumer", "agent", "--status", "active", "--expiring-in", "2m", "--cursor", "next", "--limit", "3"}, errWriter{err: errors.New("lease json fail")}, starter); err == nil {
		t.Fatal("expected lease list json write error")
	}
	if service.leaseListReq.ConsumerID != "agent" || service.leaseListReq.ExpiringInSeconds != 120 || service.leaseListReq.Cursor != "next" || service.leaseListReq.Limit != 3 {
		t.Fatalf("lease list request = %+v", service.leaseListReq)
	}
	out.Reset()
	service.leaseListReply.Leases = nil
	if err := leaseListCommand(context.Background(), nil, &out, starter); err != nil {
		t.Fatalf("lease list empty human: %v", err)
	}
	if !strings.Contains(out.String(), "No leases.") {
		t.Fatalf("lease list empty output = %q", out.String())
	}
	if err := renderLeaseList(errWriter{err: errors.New("lease table fail")}, []runtime.Lease{{LastUsedAt: now, ExpiresAt: now}}); err == nil {
		t.Fatal("expected lease table write failure")
	}
	if err := leaseRevokeCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected lease revoke parse error")
	}
	if err := leaseRevokeCommand(context.Background(), []string{"lease-1"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected lease revoke ensure error")
	}
	service.revokeErr = errors.New("revoke fail")
	if err := leaseRevokeCommand(context.Background(), []string{"lease-1"}, &out, starter); err == nil {
		t.Fatal("expected lease revoke rpc error")
	}
	service.revokeErr = nil
	if err := leaseRevokeCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"lease-1"}, errWriter{err: errors.New("revoke json fail")}, starter); err == nil {
		t.Fatal("expected lease revoke json write error")
	}
	out.Reset()
	if err := leaseRevokeCommand(context.Background(), []string{"--all-for-consumer", "agent"}, &out, starter); err != nil {
		t.Fatalf("lease revoke all human: %v", err)
	}
	if !strings.Contains(out.String(), "Revoked 1 leases for agent") {
		t.Fatalf("lease revoke all output = %q", out.String())
	}
	service.revokeReply = runtime.RevokeLeaseResponse{Revoked: true, RevokedCount: 0}
	out.Reset()
	if err := leaseRevokeCommand(context.Background(), []string{"lease-1"}, &out, starter); err != nil {
		t.Fatalf("lease already revoked human: %v", err)
	}
	if !strings.Contains(out.String(), "already revoked") {
		t.Fatalf("lease already revoked output = %q", out.String())
	}
	service.revokeReply = runtime.RevokeLeaseResponse{}
	if err := leaseRevokeCommand(context.Background(), []string{"lease-2"}, &out, starter); err == nil {
		t.Fatal("expected lease revoke not found error")
	}
	if got := normalizeLeaseRevokeArgs([]string{"lease-1", "--all-for-consumer=agent", "--reason", "done"}); strings.Join(got, ",") != "--all-for-consumer=agent,--reason,done,lease-1" {
		t.Fatalf("normalized revoke args = %v", got)
	}
}

func TestApprovalConsumerCommandRemainingBranches(t *testing.T) {
	lockAppSeams(t)
	now := time.Date(2026, 5, 14, 1, 2, 3, 0, time.UTC)
	service := &consumerCommandRPC{
		approvalListReply: runtime.ListApprovalsResponse{Approvals: []runtime.Approval{{
			ID: "approval-1", SecretID: "secret", RequesterConsumerID: "agent", RequestedScope: "window", Status: "pending", RequestedAt: now, ExpiresAt: now.Add(time.Hour),
		}}},
		decideReply: runtime.DecideApprovalResponse{Approval: runtime.Approval{ID: "approval-1", Status: "granted"}, Changed: true},
	}
	starter := startConsumerCommandRPC(t, service)
	var out bytes.Buffer

	if err := approvalCommand(context.Background(), nil, errWriter{err: errors.New("help fail")}, starter); err == nil {
		t.Fatal("expected approval help writer failure")
	}
	if err := approvalListCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected approval list parse error")
	}
	if err := approvalListCommand(context.Background(), []string{"--status", "pending"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected approval list ensure error")
	}
	service.approvalListErr = errors.New("approval list fail")
	if err := approvalListCommand(context.Background(), nil, &out, starter); err == nil {
		t.Fatal("expected approval list rpc error")
	}
	service.approvalListErr = nil
	if err := approvalListCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--status", "pending", "--consumer", "agent"}, errWriter{err: errors.New("approval json fail")}, starter); err == nil {
		t.Fatal("expected approval list json write error")
	}
	if service.approvalListReq.Status != "pending" || service.approvalListReq.ConsumerID != "agent" {
		t.Fatalf("approval list request = %+v", service.approvalListReq)
	}
	out.Reset()
	service.approvalListReply.Approvals = nil
	if err := approvalListCommand(context.Background(), nil, &out, starter); err != nil {
		t.Fatalf("approval list empty human: %v", err)
	}
	if !strings.Contains(out.String(), "No approvals.") {
		t.Fatalf("approval list empty output = %q", out.String())
	}
	if err := renderApprovalList(errWriter{err: errors.New("approval table fail")}, []runtime.Approval{{RequestedAt: now, ExpiresAt: now}}); err == nil {
		t.Fatal("expected approval table write failure")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected approval decide parse error")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--deny", "approval-1"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected approval decide ensure error")
	}
	service.decideErr = errors.New("decide fail")
	if err := approvalDecideCommand(context.Background(), []string{"--deny", "approval-1"}, &out, starter); err == nil {
		t.Fatal("expected approval decide rpc error")
	}
	service.decideErr = nil
	if err := approvalDecideCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--deny", "--reason", "no", "approval-1"}, errWriter{err: errors.New("decide json fail")}, starter); err == nil {
		t.Fatal("expected approval decide json write error")
	}
	if service.decideReq.Decision != "deny" || service.decideReq.Reason != "no" || service.decideReq.ApprovalID != "approval-1" {
		t.Fatalf("deny request = %+v", service.decideReq)
	}
	out.Reset()
	service.decideReply.Approval.Status = "denied"
	if err := approvalDecideCommand(context.Background(), []string{"--deny", "approval-1"}, &out, starter); err != nil {
		t.Fatalf("approval deny human: %v", err)
	}
	if !strings.Contains(out.String(), "Denied approval approval-1") {
		t.Fatalf("approval deny output = %q", out.String())
	}
	out.Reset()
	service.decideReply.Approval.Status = "granted"
	if err := approvalDecideCommand(context.Background(), []string{"--grant", "--ttl", "2m", "--scope", "window", "--auth-method", "touch-id", "--hold-proof", "1500ms", "approval-1"}, &out, starter); err != nil {
		t.Fatalf("approval grant human: %v", err)
	}
	if !strings.Contains(out.String(), "Granted approval approval-1") || service.decideReq.GrantedTTLS != 120 || service.decideReq.HoldDurationMS != 1500 {
		t.Fatalf("approval grant output=%q request=%+v", out.String(), service.decideReq)
	}
	if got := normalizeApprovalDecideArgs([]string{"approval-1", "--ttl=2m", "--scope", "window"}); strings.Join(got, ",") != "--ttl=2m,--scope,window,approval-1" {
		t.Fatalf("normalized approval args = %v", got)
	}
}

func TestConfigConsumerCommandRemainingBranches(t *testing.T) {
	lockAppSeams(t)
	service := &consumerCommandRPC{
		configReply:    runtime.ConfigResponse{Config: map[string]any{"audit.retention_days": 30, "feature.enabled": true}},
		setConfigReply: runtime.ConfigValueResponse{Key: "audit.retention_days", Value: 90},
	}
	starter := startConsumerCommandRPC(t, service)
	var out bytes.Buffer

	if err := configCommand(context.Background(), nil, errWriter{err: errors.New("help fail")}, starter); err == nil {
		t.Fatal("expected config help writer failure")
	}
	if err := configShowCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected config show parse error")
	}
	if err := configShowCommand(context.Background(), nil, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected config show ensure error")
	}
	service.configErr = errors.New("config fail")
	if err := configShowCommand(context.Background(), nil, &out, starter); err == nil {
		t.Fatal("expected config show rpc error")
	}
	service.configErr = nil
	if err := configShowCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), nil, errWriter{err: errors.New("config json fail")}, starter); err == nil {
		t.Fatal("expected config show json write error")
	}
	if err := configShowCommand(context.Background(), nil, errWriter{err: errors.New("config table fail")}, starter); err == nil {
		t.Fatal("expected config show table write error")
	}
	if err := configGetCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected config get parse error")
	}
	if err := configGetCommand(context.Background(), []string{"audit.retention_days"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected config get ensure error")
	}
	service.configErr = errors.New("config get fail")
	if err := configGetCommand(context.Background(), []string{"audit.retention_days"}, &out, starter); err == nil {
		t.Fatal("expected config get rpc error")
	}
	service.configErr = nil
	if err := configGetCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"audit.retention_days"}, errWriter{err: errors.New("config get json fail")}, starter); err == nil {
		t.Fatal("expected config get json write error")
	}
	if err := configGetCommand(context.Background(), []string{"feature.enabled"}, errWriter{err: errors.New("config get human fail")}, starter); err == nil {
		t.Fatal("expected config get human write error")
	}
	if err := configSetCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected config set parse error")
	}
	if err := configSetCommand(context.Background(), []string{"audit.retention_days", "[bad"}, &out, starter); err == nil {
		t.Fatal("expected config set parse value error")
	}
	if err := configSetCommand(context.Background(), []string{"audit.retention_days", "90"}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected config set ensure error")
	}
	service.setConfigErr = errors.New("set config fail")
	if err := configSetCommand(context.Background(), []string{"audit.retention_days", "90"}, &out, starter); err == nil {
		t.Fatal("expected config set rpc error")
	}
	service.setConfigErr = nil
	if err := configSetCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"audit.retention_days", "90"}, errWriter{err: errors.New("set config json fail")}, starter); err == nil {
		t.Fatal("expected config set json write error")
	}
	if err := configSetCommand(context.Background(), []string{"audit.retention_days", "90"}, errWriter{err: errors.New("set config human fail")}, starter); err == nil {
		t.Fatal("expected config set human write error")
	}
	if service.setConfigReq.Key != "audit.retention_days" || service.setConfigReq.Actor != "cli" {
		t.Fatalf("set config request = %+v", service.setConfigReq)
	}
}

func TestPolicyConsumerCommandRemainingBranches(t *testing.T) {
	lockAppSeams(t)
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	doc := runtime.PolicyDocument{Version: "v1", Rules: []runtime.PolicyRule{{
		ID:       "allow",
		Match:    runtime.PolicyMatch{Consumer: "agent", Secret: "secret", Scope: "window"},
		Decision: "allow",
		TTLS:     60,
	}}}
	writePolicyFile(t, policyPath, doc)
	service := &consumerCommandRPC{
		policyReply:    runtime.PolicyResponse{PolicyDocument: doc},
		setPolicyReply: runtime.PolicyResponse{PolicyDocument: doc},
	}
	starter := startConsumerCommandRPC(t, service)
	var out bytes.Buffer

	if err := policyCommand(context.Background(), nil, errWriter{err: errors.New("help fail")}, starter); err == nil {
		t.Fatal("expected policy help writer failure")
	}
	if err := policyShowCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected policy show parse error")
	}
	if err := policyShowCommand(context.Background(), nil, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected policy show ensure error")
	}
	service.policyErr = errors.New("policy fail")
	if err := policyShowCommand(context.Background(), nil, &out, starter); err == nil {
		t.Fatal("expected policy show rpc error")
	}
	service.policyErr = nil
	if err := policyShowCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), nil, errWriter{err: errors.New("policy json fail")}, starter); err == nil {
		t.Fatal("expected policy show json write error")
	}
	if err := policyShowCommand(context.Background(), nil, errWriter{err: errors.New("policy table fail")}, starter); err == nil {
		t.Fatal("expected policy show table write error")
	}
	if err := policySetCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected policy set parse error")
	}
	if err := policySetCommand(context.Background(), []string{"--file", policyPath}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected policy set ensure error")
	}
	service.setPolicyErr = errors.New("set policy fail")
	if err := policySetCommand(context.Background(), []string{"--file", policyPath}, &out, starter); err == nil {
		t.Fatal("expected policy set rpc error")
	}
	service.setPolicyErr = nil
	if err := policySetCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--file", policyPath}, errWriter{err: errors.New("set policy json fail")}, starter); err == nil {
		t.Fatal("expected policy set json write error")
	}
	if err := policySetCommand(context.Background(), []string{"--file", policyPath, "--force"}, errWriter{err: errors.New("set policy human fail")}, starter); err == nil {
		t.Fatal("expected policy set human write error")
	}
	if !service.setPolicyReq.Force || service.setPolicyReq.IfMatch != "v1" || service.setPolicyReq.UpdatedBy != "cli" {
		t.Fatalf("set policy request = %+v", service.setPolicyReq)
	}
	if err := policyValidateCommand(context.Background(), []string{"--bad"}, &out, starter); err == nil {
		t.Fatal("expected policy validate parse error")
	}
	if err := policyValidateCommand(context.Background(), []string{"--file", policyPath}, &out, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected policy validate ensure error")
	}
	service.setPolicyErr = errors.New("validate fail")
	if err := policyValidateCommand(context.Background(), []string{"--file", policyPath}, &out, starter); err == nil {
		t.Fatal("expected policy validate rpc error")
	}
	service.setPolicyErr = nil
	if err := policyValidateCommand(contextWithGlobalFlags(context.Background(), globalFlags{json: true}), []string{"--file", policyPath}, errWriter{err: errors.New("validate json fail")}, starter); err == nil {
		t.Fatal("expected policy validate json write error")
	}
	if err := policyValidateCommand(context.Background(), []string{"--file", policyPath}, errWriter{err: errors.New("validate human fail")}, starter); err == nil {
		t.Fatal("expected policy validate human write error")
	}
	if !service.setPolicyReq.ValidateOnly {
		t.Fatalf("validate policy request = %+v", service.setPolicyReq)
	}
}
