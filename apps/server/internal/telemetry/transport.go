package telemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 2 * time.Second

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	Endpoint   string
	HTTPClient HTTPDoer
	Timeout    time.Duration
	Now        func() time.Time
}

func (c Client) endpoint() string {
	if strings.TrimSpace(c.Endpoint) != "" {
		return strings.TrimSpace(c.Endpoint)
	}
	return strings.TrimSpace(Endpoint)
}

func ValidateEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" || parsed.Host != "telemetry.gethasp.com" || parsed.Path != "/v1/cli/ping" || parsed.RawQuery != "" {
		return "", errors.New("untrusted telemetry endpoint")
	}
	return parsed.String(), nil
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return NowFn()
}

func (c Client) httpClient() HTTPDoer {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

func (c Client) TrySendPing(ctx context.Context, store Store, version string) error {
	endpoint, err := ValidateEndpoint(c.endpoint())
	if err != nil || DisabledByEnv() || endpoint == "" {
		return nil
	}
	state, err := store.Load()
	if err != nil || !state.Enabled {
		return nil
	}
	now := c.now()
	if !state.LastPingAt.IsZero() && now.Sub(state.LastPingAt) < 23*time.Hour {
		return nil
	}
	payload, state, err := BuildPayload(state, BuildOptions{HaspVersion: version, InstallMethod: "unknown", Now: now})
	if err != nil {
		return nil
	}
	body, err := EncodePayload(payload)
	if err != nil {
		return nil
	}
	if err := c.postJSON(ctx, endpoint, body); err != nil {
		return nil
	}
	state.LastPingAt = now
	state.Commands24h = 0
	state.RootCommands = Counts{}
	state.Setup = Counts{}
	state.Features = Counts{}
	state.Safety = Counts{}
	state.Errors = Counts{}
	state.Performance = Counts{}
	_ = store.Save(state)
	return nil
}

func (c Client) SendErasure(ctx context.Context, installHash string) error {
	endpoint, err := ValidateEndpoint(c.endpoint())
	if err != nil || endpoint == "" || strings.TrimSpace(installHash) == "" || DisabledByEnv() {
		return nil
	}
	erasureEndpoint := strings.TrimSuffix(endpoint, "/v1/cli/ping") + "/v1/cli/erasure"
	body := []byte(fmt.Sprintf(`{"schema_version":%d,"install_id_hash":%q,"action":"delete"}`, SchemaVersion, installHash))
	return c.postJSON(ctx, erasureEndpoint, body)
}

func (c Client) SendErasures(ctx context.Context, installHashes []string) error {
	for _, hash := range installHashes {
		if err := c.SendErasure(ctx, hash); err != nil {
			return err
		}
	}
	return nil
}

func (c Client) postJSON(ctx context.Context, endpoint string, body []byte) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "hasp-cli-telemetry")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telemetry endpoint returned %s", resp.Status)
	}
	return nil
}
