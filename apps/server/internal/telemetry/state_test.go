package telemetry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTelemetryTestStore(t *testing.T) Store {
	t.Helper()
	store := Store{Path: filepath.Join(t.TempDir(), "telemetry.json")}
	origRandom := RandomFn
	origNow := NowFn
	t.Cleanup(func() {
		RandomFn = origRandom
		NowFn = origNow
	})
	RandomFn = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i + 1)
		}
		return len(p), nil
	}
	NowFn = func() time.Time { return time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC) }
	return store
}

func TestStoreDefaultDisabledAndEnvBlocksEnable(t *testing.T) {
	store := withTelemetryTestStore(t)
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if state.Enabled {
		t.Fatal("telemetry should default disabled")
	}

	t.Setenv(EnvDisabled, "1")
	if _, err := store.Enable(NowFn()); err == nil {
		t.Fatal("expected env-disabled enable failure")
	}
	if _, err := os.Stat(store.Path); !os.IsNotExist(err) {
		t.Fatalf("enable under env kill switch wrote state file: %v", err)
	}
}

func TestStoreEnableWrites0600AndRecordsOnlyWhenEnabled(t *testing.T) {
	store := withTelemetryTestStore(t)
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("record disabled: %v", err)
	}
	state, _ := store.Load()
	if state.CommandsTotal != 0 {
		t.Fatalf("disabled record mutated counters: %+v", state)
	}

	if _, err := store.Enable(NowFn()); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := store.RecordRootCommand("../../secret", NowFn()); err != nil {
		t.Fatalf("record disallowed: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if state.Commands24h != 1 || state.CommandsTotal != 1 || state.RootCommands["run"] != 1 {
		t.Fatalf("unexpected counters: %+v", state)
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode = %o, want 0600", got)
	}
}

func TestYearlyRotationKeepsPriorHashForErasure(t *testing.T) {
	store := withTelemetryTestStore(t)
	first := time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC)
	second := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	state, err := store.Enable(first)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	firstHash := InstallHash(state.InstallID, state.InstallYear)
	RandomFn = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(255 - i)
		}
		return len(p), nil
	}
	payload, rotated, err := BuildPayload(state, BuildOptions{HaspVersion: "1.0.5", InstallMethod: "source", Now: second})
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	if payload.InstallIDHash == firstHash {
		t.Fatal("payload did not rotate install hash")
	}
	if len(rotated.ErasureIDs) != 1 || rotated.ErasureIDs[0].Hash != firstHash {
		t.Fatalf("prior hash not retained for erasure: %+v", rotated.ErasureIDs)
	}
	if err := store.Save(rotated); err != nil {
		t.Fatalf("save rotated: %v", err)
	}
	hashes, err := store.Forget()
	if err != nil {
		t.Fatalf("forget: %v", err)
	}
	joined := strings.Join(hashes, ",")
	if !strings.Contains(joined, firstHash) || !strings.Contains(joined, payload.InstallIDHash) {
		t.Fatalf("forget hashes = %v, want current and prior", hashes)
	}
	if _, err := os.Stat(store.Path); !os.IsNotExist(err) {
		t.Fatalf("forget left local state: %v", err)
	}
}

func TestPayloadFiltersAllowlistAndRejectsForbiddenKeys(t *testing.T) {
	store := withTelemetryTestStore(t)
	state, err := store.Enable(NowFn())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	state.RootCommands = Counts{"run": 2, "secret-name": 99}
	state.Features = Counts{"run": 1, "path": 9}
	payload, _, err := BuildPayload(state, BuildOptions{HaspVersion: "1.0.5", InstallMethod: "homebrew", Now: NowFn()})
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	data, err := EncodePayload(payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, forbidden := range []string{"path", "repo", "alias", "ref", "argv", "stdout", "stderr", "hostname", "username"} {
		if bytes.Contains(data, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("payload contains forbidden key %q: %s", forbidden, data)
		}
	}
	if bytes.Contains(data, []byte("secret-name")) {
		t.Fatalf("payload leaked disallowed command: %s", data)
	}
}

func TestClientEndpointPinningAndSendResetsDailyCounters(t *testing.T) {
	store := withTelemetryTestStore(t)
	state, err := store.Enable(NowFn())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	state.Commands24h = 3
	state.CommandsTotal = 7
	state.RootCommands = Counts{"run": 3}
	state.Features = Counts{"run": 1}
	state.Safety = Counts{"repo_blocks": 1}
	if err := store.Save(state); err != nil {
		t.Fatalf("save: %v", err)
	}

	doer := &captureDoer{}
	client := Client{Endpoint: "http://example.com/v1/cli/ping", HTTPClient: doer, Now: NowFn}
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("try untrusted: %v", err)
	}
	if doer.calls != 0 {
		t.Fatal("untrusted endpoint was used")
	}

	client.Endpoint = TrustedEndpoint
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("try trusted: %v", err)
	}
	if doer.calls != 1 {
		t.Fatalf("trusted endpoint calls = %d", doer.calls)
	}
	if doer.url != TrustedEndpoint {
		t.Fatalf("url = %q", doer.url)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatalf("load after send: %v", err)
	}
	if after.Commands24h != 0 || len(after.RootCommands) != 0 || len(after.Features) != 0 || len(after.Safety) != 0 {
		t.Fatalf("daily counters not reset: %+v", after)
	}
}

type captureDoer struct {
	calls int
	url   string
	body  []byte
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.url = req.URL.String()
	body, _ := io.ReadAll(req.Body)
	d.body = body
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Status:     "204 No Content",
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}
