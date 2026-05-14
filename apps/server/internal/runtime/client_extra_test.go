package runtime

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type revokeFalseRPC struct{}

func (revokeFalseRPC) RevokeSession(_ RevokeSessionRequest, reply *RevokeSessionResponse) error {
	*reply = RevokeSessionResponse{Revoked: false}
	return nil
}

type pingOnlyRPC struct{}

func (pingOnlyRPC) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{Name: "hasp"}
	return nil
}

type coverageRPC struct{}

func (coverageRPC) ListLeases(_ ListLeasesRequest, reply *ListLeasesResponse) error {
	*reply = ListLeasesResponse{}
	return nil
}

func (coverageRPC) AccessMatrix(_ AccessMatrixRequest, reply *AccessMatrixResponse) error {
	*reply = AccessMatrixResponse{}
	return nil
}

func (coverageRPC) Policy(_ PolicyGetRequest, reply *PolicyResponse) error {
	*reply = PolicyResponse{}
	return nil
}

func (coverageRPC) SetPolicy(_ PolicySetRequest, reply *PolicyResponse) error {
	*reply = PolicyResponse{}
	return nil
}

func (coverageRPC) Config(_ ConfigGetRequest, reply *ConfigResponse) error {
	*reply = ConfigResponse{}
	return nil
}

func (coverageRPC) SetConfig(_ ConfigSetRequest, reply *ConfigValueResponse) error {
	*reply = ConfigValueResponse{}
	return nil
}

func (coverageRPC) Integrations(_ IntegrationGetRequest, reply *IntegrationListResponse) error {
	*reply = IntegrationListResponse{}
	return nil
}

func (coverageRPC) IntegrationProfiles(_ IntegrationProfilesRequest, reply *IntegrationProfilesResponse) error {
	*reply = IntegrationProfilesResponse{}
	return nil
}

func (coverageRPC) DoctorIntegration(_ IntegrationDoctorRPCRequest, reply *IntegrationDoctorResponse) error {
	*reply = IntegrationDoctorResponse{}
	return nil
}

func (coverageRPC) RevokeLease(_ RevokeLeaseRequest, reply *RevokeLeaseResponse) error {
	*reply = RevokeLeaseResponse{}
	return nil
}

func (coverageRPC) ListApprovals(_ ListApprovalsRequest, reply *ListApprovalsResponse) error {
	*reply = ListApprovalsResponse{}
	return nil
}

func (coverageRPC) DecideApproval(_ DecideApprovalRequest, reply *DecideApprovalResponse) error {
	*reply = DecideApprovalResponse{}
	return nil
}

func startCoverageRPCClient(t *testing.T, service any) *Client {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "hasp-client.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register rpc: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestClientCoverageRPCMethods(t *testing.T) {
	client := startCoverageRPCClient(t, coverageRPC{})
	ctx := context.Background()
	if _, err := client.ListLeases(ctx, ListLeasesRequest{}); err != nil {
		t.Fatalf("list leases: %v", err)
	}
	if _, err := client.AccessMatrix(ctx, AccessMatrixRequest{}); err != nil {
		t.Fatalf("access matrix: %v", err)
	}
	if _, err := client.Policy(ctx); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if _, err := client.SetPolicy(ctx, PolicySetRequest{}); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	if _, err := client.Config(ctx); err != nil {
		t.Fatalf("config: %v", err)
	}
	if _, err := client.SetConfig(ctx, ConfigSetRequest{}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if _, err := client.Integrations(ctx); err != nil {
		t.Fatalf("integrations: %v", err)
	}
	if _, err := client.IntegrationProfiles(ctx, IntegrationProfilesRequest{}); err != nil {
		t.Fatalf("integration profiles: %v", err)
	}
	if _, err := client.DoctorIntegration(ctx, IntegrationDoctorRPCRequest{}); err != nil {
		t.Fatalf("doctor integration: %v", err)
	}
	if _, err := client.RevokeLease(ctx, RevokeLeaseRequest{}); err != nil {
		t.Fatalf("revoke lease: %v", err)
	}
	if _, err := client.ListApprovals(ctx, ListApprovalsRequest{}); err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if _, err := client.DecideApproval(ctx, DecideApprovalRequest{}); err != nil {
		t.Fatalf("decide approval: %v", err)
	}
}

func TestClientRevokeSessionFailsWhenNotRevoked(t *testing.T) {
	socketPath := "/tmp/hasp-client-extra.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", revokeFalseRPC{}); err != nil {
		t.Fatalf("register rpc: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		if waitErr := waitForSocket(socketPath, time.Second); waitErr != nil {
			t.Fatalf("wait for socket: %v", waitErr)
		}
		client, err = Dial(context.Background(), socketPath)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.RevokeSession(context.Background(), "missing"); err == nil {
		t.Fatal("expected revoke failure when server reports not revoked")
	}
}

func TestClientRevokeSessionPropagatesCallError(t *testing.T) {
	socketPath := "/tmp/hasp-client-revoke-error.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", pingOnlyRPC{}); err != nil {
		t.Fatalf("register rpc: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.RevokeSession(context.Background(), "missing"); err == nil {
		t.Fatal("expected rpc call error")
	}
}

func TestClientCallRespectsContextCancellation(t *testing.T) {
	socketPath := "/tmp/hasp-client-cancel.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", revokeFalseRPC{}); err != nil {
		t.Fatalf("register rpc: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ResolveSession(ctx, "token"); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestClientCloseIdempotentErrorPath(t *testing.T) {
	socketPath := "/tmp/hasp-client-close.sock"
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", revokeFalseRPC{}); err != nil {
		t.Fatalf("register rpc: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = client.Close()
	if err := client.Close(); err == nil {
		t.Fatal("expected close error after connection shutdown")
	}
}
