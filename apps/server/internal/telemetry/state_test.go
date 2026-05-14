package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func withTelemetryTestStore(t *testing.T) Store {
	t.Helper()
	store := Store{Path: filepath.Join(t.TempDir(), "telemetry.json")}
	origRandom := RandomFn
	origNow := NowFn
	origMarshalIndent := jsonMarshalIndentFn
	origMarshal := jsonMarshalFn
	t.Cleanup(func() {
		RandomFn = origRandom
		NowFn = origNow
		jsonMarshalIndentFn = origMarshalIndent
		jsonMarshalFn = origMarshal
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
	if DefaultStore().Path != "" {
		t.Fatal("default store should not set an explicit path")
	}
	t.Setenv("HASP_TELEMETRY_TEST_STATE", store.Path)
	if path, err := DefaultStore().statePath(); err != nil || path != store.Path {
		t.Fatalf("default store test path = %q, %v", path, err)
	}
	t.Setenv("HASP_TELEMETRY_TEST_STATE", "")
	t.Setenv("HASP_TELEMETRY_ALLOW_DEFAULT_STATE_PATH", "1")
	origStatePath := StatePathFn
	StatePathFn = func() (string, error) { return store.Path, nil }
	if path, err := DefaultStore().statePath(); err != nil || path != store.Path {
		t.Fatalf("allowed default state path = %q, %v", path, err)
	}
	StatePathFn = origStatePath
	t.Setenv("HASP_TELEMETRY_ALLOW_DEFAULT_STATE_PATH", "")
	t.Setenv("HASP_TELEMETRY_TEST_STATE", store.Path)
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

func TestStoreLoadAndSaveErrorBranches(t *testing.T) {
	store := withTelemetryTestStore(t)
	if cloned := (Counts{"run": 0, "status": 1}).cloneAllowed(allowedRootCommands); len(cloned) != 1 || cloned["status"] != 1 {
		t.Fatalf("clone allowed filtered counts = %+v", cloned)
	}

	if err := os.WriteFile(store.Path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid state: %v", err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatalf("load invalid json: %v", err)
	}
	if state.RootCommands == nil || state.Setup == nil {
		t.Fatalf("invalid json did not normalize empty state: %+v", state)
	}

	origRead := readFileFn
	readFileFn = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	if _, err := store.Load(); err == nil {
		t.Fatal("expected load read failure")
	}
	readFileFn = origRead

	origMkdir := mkdirAllFn
	mkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	if err := store.Save(State{}); err == nil {
		t.Fatal("expected mkdir failure")
	}
	mkdirAllFn = origMkdir

	origWrite := writeFileFn
	writeFileFn = func(string, []byte, os.FileMode) error { return errors.New("write denied") }
	if err := store.Save(State{}); err == nil {
		t.Fatal("expected write failure")
	}
	writeFileFn = origWrite

	jsonMarshalIndentFn = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal denied")
	}
	if err := store.Save(State{}); err == nil {
		t.Fatal("expected marshal failure")
	}
	jsonMarshalIndentFn = json.MarshalIndent

	if err := (Store{}).Save(State{}); err == nil {
		t.Fatal("expected save state path failure")
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

func TestStoreStateMutationFailureBranches(t *testing.T) {
	store := withTelemetryTestStore(t)

	origRandom := RandomFn
	RandomFn = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if _, err := store.Enable(NowFn()); err == nil {
		t.Fatal("expected enable random failure")
	}
	RandomFn = origRandom

	if err := store.Save(State{Enabled: true}); err != nil {
		t.Fatalf("save enabled state: %v", err)
	}
	origWrite := writeFileFn
	writeFileFn = func(string, []byte, os.FileMode) error { return errors.New("write denied") }
	if _, err := store.Enable(NowFn()); err == nil {
		t.Fatal("expected enable save failure")
	}
	if _, err := store.Disable(); err == nil {
		t.Fatal("expected disable save failure")
	}
	writeFileFn = origWrite

	origRead := readFileFn
	readFileFn = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	if _, err := store.Enable(NowFn()); err == nil {
		t.Fatal("expected enable load failure")
	}
	if _, err := store.Disable(); err == nil {
		t.Fatal("expected disable load failure")
	}
	if _, err := store.Forget(); err == nil {
		t.Fatal("expected forget load failure")
	}
	readFileFn = origRead

	if err := store.Save(State{InstallID: " install ", InstallYear: 2026, ErasureIDs: []ErasureID{{Hash: " old "}}}); err != nil {
		t.Fatalf("save forget state: %v", err)
	}
	origRemove := removeFn
	removeFn = func(string) error { return errors.New("remove denied") }
	hashes, err := store.Forget()
	if err == nil {
		t.Fatal("expected forget remove failure")
	}
	if len(hashes) != 2 {
		t.Fatalf("forget remove failure hashes = %v", hashes)
	}
	removeFn = origRemove

	t.Setenv("HASP_TELEMETRY_TEST_STATE", store.Path)
	readFileFn = func(path string) ([]byte, error) {
		t.Setenv("HASP_TELEMETRY_TEST_STATE", "")
		return os.ReadFile(path)
	}
	hashes, err = (Store{}).Forget()
	if err == nil || len(hashes) == 0 {
		t.Fatalf("expected forget state path failure with retained hashes, hashes=%v err=%v", hashes, err)
	}
	readFileFn = origRead

	origStatePath := StatePathFn
	StatePathFn = func() (string, error) { return "", errors.New("path denied") }
	if _, err := (Store{}).Forget(); err == nil {
		t.Fatal("expected forget state path failure")
	}
	StatePathFn = origStatePath
}

func TestRecordRootCommandFailureBranches(t *testing.T) {
	store := withTelemetryTestStore(t)
	origRead := readFileFn
	readFileFn = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("record should swallow load errors: %v", err)
	}
	readFileFn = origRead

	if err := store.Save(State{Enabled: true}); err != nil {
		t.Fatalf("save enabled state: %v", err)
	}
	rawState := `{"enabled":true}` + "\n"
	if err := os.WriteFile(store.Path, []byte(rawState), 0o600); err != nil {
		t.Fatalf("write raw state: %v", err)
	}
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("record should initialize root commands: %v", err)
	}

	if err := os.WriteFile(store.Path, []byte(rawState), 0o600); err != nil {
		t.Fatalf("write raw state for random failure: %v", err)
	}
	origRandom := RandomFn
	RandomFn = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("record should swallow install id errors: %v", err)
	}
	RandomFn = origRandom

	t.Setenv(EnvDisabled, "on")
	if err := store.RecordRootCommand("run", NowFn()); err != nil {
		t.Fatalf("disabled record: %v", err)
	}
}

func TestStoreDisablePersistsOptOut(t *testing.T) {
	store := withTelemetryTestStore(t)
	if _, err := store.Enable(NowFn()); err != nil {
		t.Fatalf("enable: %v", err)
	}

	disabled, err := store.Disable()
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled.Enabled {
		t.Fatal("disable returned enabled state")
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Enabled {
		t.Fatalf("disable did not persist: %+v", reloaded)
	}
}

func TestPayloadValidationRejectsMalformedFields(t *testing.T) {
	valid := Payload{
		SchemaVersion: SchemaVersion,
		InstallIDHash: strings.Repeat("a", 64),
		HaspVersion:   "1.0.5",
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		InstallMethod: "source",
		TopCommands:   []CommandCount{{Name: "run", Count: 1}},
		Setup:         Counts{"started": 1},
		Features:      Counts{"run": 1},
		Safety:        Counts{"repo_blocks": 1},
		Errors:        Counts{"usage": 1},
		Performance:   Counts{"command_duration_bucket": 1},
	}
	if err := ValidatePayload(valid); err != nil {
		t.Fatalf("valid payload: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Payload)
	}{
		{name: "schema", mutate: func(p *Payload) { p.SchemaVersion = 99 }},
		{name: "missing hash", mutate: func(p *Payload) { p.InstallIDHash = "" }},
		{name: "bad hash token", mutate: func(p *Payload) { p.InstallIDHash = strings.Repeat("/", 64) }},
		{name: "bad hash length", mutate: func(p *Payload) { p.InstallIDHash = "abc" }},
		{name: "bad version", mutate: func(p *Payload) { p.HaspVersion = "1.0.5 beta!" }},
		{name: "bad os", mutate: func(p *Payload) { p.OS = "plan9" }},
		{name: "bad arch", mutate: func(p *Payload) { p.Arch = "mips" }},
		{name: "bad install method", mutate: func(p *Payload) { p.InstallMethod = "curl | sh" }},
		{name: "bad command", mutate: func(p *Payload) { p.TopCommands = []CommandCount{{Name: "rm", Count: 1}} }},
		{name: "bad command count", mutate: func(p *Payload) { p.TopCommands = []CommandCount{{Name: "run", Count: 0}} }},
		{name: "bad setup", mutate: func(p *Payload) { p.Setup = Counts{"secret": 1} }},
		{name: "bad feature", mutate: func(p *Payload) { p.Features = Counts{"secret": 1} }},
		{name: "bad safety", mutate: func(p *Payload) { p.Safety = Counts{"secret": 1} }},
		{name: "bad error", mutate: func(p *Payload) { p.Errors = Counts{"secret": 1} }},
		{name: "bad performance", mutate: func(p *Payload) { p.Performance = Counts{"secret": 1} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := valid
			tc.mutate(&payload)
			if _, err := EncodePayload(payload); err == nil {
				t.Fatal("expected payload validation failure")
			}
		})
	}
}

func TestEncodePayloadPropagatesMarshalFailure(t *testing.T) {
	origMarshal := jsonMarshalFn
	jsonMarshalFn = func(any) ([]byte, error) {
		return nil, errors.New("marshal denied")
	}
	t.Cleanup(func() { jsonMarshalFn = origMarshal })
	valid := Payload{
		SchemaVersion: SchemaVersion,
		InstallIDHash: strings.Repeat("a", 64),
		HaspVersion:   "1.0.5",
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		InstallMethod: "source",
		PeriodHours:   defaultPeriodHours,
	}
	if _, err := EncodePayload(valid); err == nil {
		t.Fatal("expected marshal failure")
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

func TestBuildPayloadDefaultsAndFilters(t *testing.T) {
	store := withTelemetryTestStore(t)
	state, err := store.Enable(NowFn())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	state.Commands24h = -1
	state.CommandsTotal = -2
	state.RootCommands = Counts{}
	for _, command := range []string{"run", "status", "setup", "secret", "policy", "config", "agent", "app", "audit", "lease", "approval"} {
		state.RootCommands[command] = 1
	}
	payload, _, err := BuildPayload(state, BuildOptions{})
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	if payload.InstallMethod != "unknown" || payload.Commands24h != 0 || payload.CommandsTotal != 0 {
		t.Fatalf("defaults not applied: %+v", payload)
	}
	if len(payload.TopCommands) != 10 {
		t.Fatalf("top commands length = %d, want 10", len(payload.TopCommands))
	}
}

func TestBuildPayloadRejectsDisabledAndRandomFailure(t *testing.T) {
	if _, _, err := BuildPayload(State{}, BuildOptions{Now: NowFn()}); err == nil {
		t.Fatal("expected disabled payload failure")
	}
	origRandom := RandomFn
	RandomFn = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if _, _, err := BuildPayload(State{Enabled: true}, BuildOptions{Now: NowFn()}); err == nil {
		t.Fatal("expected install id failure")
	}
	RandomFn = origRandom
}

func TestNormalizeAndDedupeHelpers(t *testing.T) {
	NowFn = func() time.Time { return time.Date(2026, 5, 13, 0, 0, 0, 0, time.UTC) }
	state := State{
		InstallID: " install ",
		ErasureIDs: []ErasureID{
			{Hash: " keep ", ExpiresAt: NowFn().Add(time.Hour)},
			{Hash: " expired ", ExpiresAt: NowFn().Add(-time.Hour)},
			{Hash: "   "},
		},
	}
	normalizeState(&state)
	if state.InstallID != "install" || len(state.ErasureIDs) != 1 || state.ErasureIDs[0].Hash != "keep" {
		t.Fatalf("normalize = %+v", state)
	}
	if got := dedupeStrings([]string{" a ", "a", "", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("dedupe = %v", got)
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

func TestClientSendErasuresPostsDeleteRequests(t *testing.T) {
	doer := &captureDoer{}
	client := Client{Endpoint: TrustedEndpoint, HTTPClient: doer, Timeout: time.Second}
	if err := client.SendErasures(context.Background(), []string{" hash-one ", "", "hash-two"}); err != nil {
		t.Fatalf("send erasures: %v", err)
	}
	if doer.calls != 2 {
		t.Fatalf("erasure calls = %d, want 2", doer.calls)
	}
	if doer.url != "https://telemetry.gethasp.com/v1/cli/erasure" {
		t.Fatalf("erasure url = %q", doer.url)
	}
	if !bytes.Contains(doer.body, []byte(`"install_id_hash":"hash-two"`)) || !bytes.Contains(doer.body, []byte(`"action":"delete"`)) {
		t.Fatalf("unexpected erasure body: %s", doer.body)
	}
}

func TestClientSendErasureSkipsUnsafeInputs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		hash     string
		disabled string
	}{
		{name: "empty endpoint", endpoint: "", hash: "hash"},
		{name: "untrusted endpoint", endpoint: "https://example.com/v1/cli/ping", hash: "hash"},
		{name: "blank hash", endpoint: TrustedEndpoint, hash: "  "},
		{name: "disabled by env", endpoint: TrustedEndpoint, hash: "hash", disabled: "yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvDisabled, tc.disabled)
			doer := &captureDoer{}
			client := Client{Endpoint: tc.endpoint, HTTPClient: doer}
			if err := client.SendErasure(context.Background(), tc.hash); err != nil {
				t.Fatalf("send erasure: %v", err)
			}
			if doer.calls != 0 {
				t.Fatalf("unsafe erasure input triggered %d calls", doer.calls)
			}
		})
	}
}

func TestClientSendErasuresStopsOnPostFailure(t *testing.T) {
	client := Client{
		Endpoint:   TrustedEndpoint,
		HTTPClient: &errorDoer{err: errors.New("network down")},
	}
	if err := client.SendErasures(context.Background(), []string{"hash-one", "hash-two"}); err == nil {
		t.Fatal("expected erasure send failure")
	}
}

func TestClientDefaultHelpersAndValidationBranches(t *testing.T) {
	origEndpoint := Endpoint
	Endpoint = " " + TrustedEndpoint + " "
	t.Cleanup(func() { Endpoint = origEndpoint })
	client := Client{}
	if client.endpoint() != TrustedEndpoint {
		t.Fatalf("default endpoint = %q", client.endpoint())
	}
	if client.now().IsZero() {
		t.Fatal("default now returned zero")
	}
	if client.httpClient() == nil {
		t.Fatal("default http client is nil")
	}
	if _, err := ValidateEndpoint("://bad"); err == nil {
		t.Fatal("expected parse failure")
	}
	if _, err := ValidateEndpoint(TrustedEndpoint + "?x=1"); err == nil {
		t.Fatal("expected query rejection")
	}
}

func TestClientTrySendPingSkipsAndFailureBranches(t *testing.T) {
	store := withTelemetryTestStore(t)
	client := Client{Endpoint: TrustedEndpoint, HTTPClient: &captureDoer{}, Now: NowFn}
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("disabled send: %v", err)
	}
	state, err := store.Enable(NowFn())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	state.LastPingAt = NowFn().Add(-time.Hour)
	if err := store.Save(state); err != nil {
		t.Fatalf("save recent state: %v", err)
	}
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("recent send: %v", err)
	}
	if client.HTTPClient.(*captureDoer).calls != 0 {
		t.Fatal("recent ping should not send")
	}

	origRead := readFileFn
	readFileFn = func(string) ([]byte, error) { return nil, errors.New("read denied") }
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("load failure should be swallowed: %v", err)
	}
	readFileFn = origRead

	state.LastPingAt = time.Time{}
	if err := store.Save(state); err != nil {
		t.Fatalf("save stale state: %v", err)
	}
	client.HTTPClient = &errorDoer{err: errors.New("network down")}
	if err := client.TrySendPing(context.Background(), store, "bad version!"); err != nil {
		t.Fatalf("payload or send failure should be swallowed: %v", err)
	}
	state.LastPingAt = time.Time{}
	state.InstallID = ""
	state.InstallYear = 0
	if err := store.Save(state); err != nil {
		t.Fatalf("save state without install id: %v", err)
	}
	origRandom := RandomFn
	RandomFn = func([]byte) (int, error) { return 0, errors.New("entropy failed") }
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("payload build failure should be swallowed: %v", err)
	}
	RandomFn = origRandom
	if err := store.Save(state); err != nil {
		t.Fatalf("restore sendable state: %v", err)
	}
	origMarshal := jsonMarshalFn
	jsonMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal denied") }
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("payload encode failure should be swallowed: %v", err)
	}
	jsonMarshalFn = origMarshal
	client.HTTPClient = &errorDoer{err: errors.New("network down")}
	if err := client.TrySendPing(context.Background(), store, "1.0.5"); err != nil {
		t.Fatalf("post failure should be swallowed: %v", err)
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

func TestClientPostJSONFailureBranches(t *testing.T) {
	client := Client{HTTPClient: &captureDoer{statusCode: http.StatusInternalServerError, status: "500 Internal Server Error"}}
	if err := client.postJSON(context.Background(), TrustedEndpoint, []byte("{}")); err == nil {
		t.Fatal("expected status failure")
	}

	client.HTTPClient = &errorDoer{err: context.DeadlineExceeded}
	client.Timeout = time.Nanosecond
	if err := client.postJSON(context.Background(), TrustedEndpoint, []byte("{}")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}

	client.HTTPClient = &captureDoer{}
	if err := client.postJSON(context.Background(), "http://[::1\n", []byte("{}")); err == nil {
		t.Fatal("expected request creation failure")
	}
}

type captureDoer struct {
	calls      int
	url        string
	body       []byte
	statusCode int
	status     string
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	d.url = req.URL.String()
	body, _ := io.ReadAll(req.Body)
	d.body = body
	statusCode := d.statusCode
	if statusCode == 0 {
		statusCode = http.StatusNoContent
	}
	status := d.status
	if status == "" {
		status = "204 No Content"
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     status,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

type errorDoer struct {
	err error
}

func (d *errorDoer) Do(*http.Request) (*http.Response, error) {
	return nil, d.err
}
