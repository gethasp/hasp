package runtime

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
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
