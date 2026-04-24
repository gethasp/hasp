package runtime

import (
	"context"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

type Client struct {
	conn   net.Conn
	client *rpc.Client
}

func Dial(ctx context.Context, socketPath string) (*Client, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		client: rpc.NewClientWithCodec(jsonrpc.NewClientCodec(conn)),
	}, nil
}

func (c *Client) Close() error {
	errClient := c.client.Close()
	errConn := c.conn.Close()
	if errClient != nil {
		return errClient
	}
	return errConn
}

func (c *Client) Ping(ctx context.Context) (PingResponse, error) {
	var reply PingResponse
	err := c.call(ctx, "HASP.Ping", PingRequest{}, &reply)
	return reply, err
}

func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var reply StatusResponse
	err := c.call(ctx, "HASP.Status", StatusRequest{}, &reply)
	return reply, err
}

func (c *Client) OpenSession(ctx context.Context, req OpenSessionRequest) (OpenSessionResponse, error) {
	var reply OpenSessionResponse
	err := c.call(ctx, "HASP.OpenSession", req, &reply)
	return reply, err
}

func (c *Client) RevokeSession(ctx context.Context, token string) error {
	var reply RevokeSessionResponse
	if err := c.call(ctx, "HASP.RevokeSession", RevokeSessionRequest{SessionToken: token}, &reply); err != nil {
		return err
	}
	if !reply.Revoked {
		return fmt.Errorf("session token not found")
	}
	return nil
}

func (c *Client) RevokeAllSessions(ctx context.Context) (RevokeAllSessionsResponse, error) {
	var reply RevokeAllSessionsResponse
	err := c.call(ctx, "HASP.RevokeAllSessions", RevokeAllSessionsRequest{}, &reply)
	return reply, err
}

func (c *Client) LockVault(ctx context.Context) (LockVaultResponse, error) {
	var reply LockVaultResponse
	err := c.call(ctx, "HASP.LockVault", LockVaultRequest{}, &reply)
	return reply, err
}

func (c *Client) ResolveSession(ctx context.Context, token string) (ResolveSessionResponse, error) {
	var reply ResolveSessionResponse
	err := c.call(ctx, "HASP.ResolveSession", ResolveSessionRequest{SessionToken: token}, &reply)
	return reply, err
}

func (c *Client) RegisterProcess(ctx context.Context, token string, pid int) error {
	var reply RegisterProcessResponse
	if err := c.call(ctx, "HASP.RegisterProcess", RegisterProcessRequest{SessionToken: token, PID: pid}, &reply); err != nil {
		return err
	}
	if !reply.Registered {
		return fmt.Errorf("process registration failed")
	}
	return nil
}

func (c *Client) ResolveProcess(ctx context.Context, pid int) (ResolveProcessResponse, error) {
	var reply ResolveProcessResponse
	err := c.call(ctx, "HASP.ResolveProcess", ResolveProcessRequest{PID: pid}, &reply)
	return reply, err
}

func (c *Client) call(ctx context.Context, method string, req any, reply any) error {
	call := c.client.Go(method, req, reply, make(chan *rpc.Call, 1))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case result := <-call.Done:
		return result.Error
	}
}
