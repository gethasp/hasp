package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestApprovalListUsesApprovalSchemaAndTopLevelDecideIsDisabled(t *testing.T) {
	lockAppSeams(t)
	service := newApprovalCommandTestRPC(t)
	starter := service.starter

	first, err := service.store.Queue(runtime.QueueApprovalInput{SecretID: "prod/db/password", RequesterConsumerID: "ci-runner", RequestedScope: "window", RequestedTTLS: 900})
	if err != nil {
		t.Fatalf("queue first approval: %v", err)
	}
	if _, err := service.store.Queue(runtime.QueueApprovalInput{SecretID: "prod/api/token", RequesterConsumerID: "human-cli", RequestedScope: "session", RequestedTTLS: 300}); err != nil {
		t.Fatalf("queue second approval: %v", err)
	}

	var listOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"approval", "list", "--status", "pending", "--json"}, bytes.NewBuffer(nil), &listOut, io.Discard, starter); err != nil {
		t.Fatalf("approval list --json: %v", err)
	}
	var list runtime.ListApprovalsResponse
	if err := json.Unmarshal(listOut.Bytes(), &list); err != nil {
		t.Fatalf("decode approval list: %v\n%s", err, listOut.String())
	}
	if list.PendingCount != 2 || len(list.Approvals) != 2 {
		t.Fatalf("approval list = %+v, want two pending", list)
	}
	for _, key := range []string{`"_schema"`, `"approvals"`, `"pending_count"`, `"oldest_pending_age_s"`} {
		if !bytes.Contains(listOut.Bytes(), []byte(key)) {
			t.Fatalf("approval list JSON missing %s: %s", key, listOut.String())
		}
	}

	err = runWithStarter(context.Background(), []string{"approval", "decide", first.ID, "--grant", "--ttl", "2m", "--scope", "window", "--auth-method", "device-owner", "--hold-proof", "1500ms", "--json"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter)
	if err == nil || !strings.Contains(err.Error(), "trusted local app approval path") {
		t.Fatalf("approval decide top-level err = %v", err)
	}
	if approvals := service.store.Snapshot(); approvals[0].Status != "pending" || approvals[1].Status != "pending" {
		t.Fatalf("top-level approval decide changed approvals: %+v", approvals)
	}
}

func TestApprovalCommandEdges(t *testing.T) {
	lockAppSeams(t)
	service := newApprovalCommandTestRPC(t)
	starter := service.starter
	var out bytes.Buffer
	if err := approvalCommand(context.Background(), nil, &out, &fakeStarter{}); err != nil {
		t.Fatalf("approval help: %v", err)
	}
	if !strings.Contains(out.String(), "usage: hasp approval") {
		t.Fatalf("approval help output = %q", out.String())
	}
	if err := approvalCommand(context.Background(), []string{"unknown"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected unknown approval subcommand")
	}
	if err := approvalListCommand(context.Background(), []string{"extra"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected approval list usage error")
	}
	if err := approvalDecideCommand(context.Background(), []string{"id"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected approval decide missing grant/deny error")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--grant", "--deny", "id"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected approval decide conflicting grant/deny error")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--grant"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected approval decide missing id error")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--grant", "--auth-method", "password", "--hold-proof", "1500ms", "id"}, &out, starter); err == nil {
		t.Fatal("expected approval decide bad auth method")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--grant", "--auth-method", "device-owner", "--hold-proof", "1s", "id"}, &out, starter); err == nil {
		t.Fatal("expected approval decide short hold proof")
	}
	if err := approvalDecideCommand(context.Background(), []string{"--deny", "--auth-method", "device-owner", "id"}, &out, starter); err == nil {
		t.Fatal("expected approval deny auth-method error")
	}
	if got := normalizeApprovalDecideArgs([]string{"id", "--reason", "no"}); strings.Join(got, ",") != "--reason,no,id" {
		t.Fatalf("normalized approval args = %v", got)
	}
}

type approvalCommandTestRPC struct {
	store   *runtime.ApprovalStore
	starter starter
}

func newApprovalCommandTestRPC(t *testing.T) *approvalCommandTestRPC {
	t.Helper()
	socketPath := shortSocketPath(t, "approval-test.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen test rpc: %v", err)
	}
	service := &approvalCommandTestRPC{store: runtime.NewApprovalStore()}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register test rpc: %v", err)
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
	service.starter = approvalCommandTestStarter{socketPath: socketPath}
	return service
}

func (s *approvalCommandTestRPC) ListApprovals(req runtime.ListApprovalsRequest, reply *runtime.ListApprovalsResponse) error {
	*reply = runtime.ListApprovalsResponse{
		Approvals:         s.store.Snapshot(),
		PendingCount:      2,
		OldestPendingAgeS: 0,
	}
	return nil
}

func (s *approvalCommandTestRPC) DecideApproval(req runtime.DecideApprovalRequest, reply *runtime.DecideApprovalResponse) error {
	if req.Decision == "grant" && (req.AuthMethod != "touch-id" && req.AuthMethod != "device-owner" || req.HoldDurationMS < 1500) {
		return errors.New("approval grant proof missing")
	}
	approval, changed, err := s.store.Decide(req.ApprovalID, runtime.ApprovalDecision{GrantedTTLS: req.GrantedTTLS, Scope: req.Scope, Reason: req.Reason}, "cli", req.Decision == "grant")
	if err != nil {
		return err
	}
	*reply = runtime.DecideApprovalResponse{Approval: approval, Changed: changed}
	if req.Decision == "grant" {
		reply.LeaseID = "lease-" + approval.ID
	}
	return nil
}

type approvalCommandTestStarter struct {
	socketPath string
}

func (s approvalCommandTestStarter) EnsureDaemon(context.Context) error { return nil }

func (s approvalCommandTestStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, s.socketPath)
}
