package telemetry

import (
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var Endpoint string

var jsonMarshalFn = json.Marshal

const TrustedEndpoint = "https://telemetry.gethasp.com/v1/cli/ping"

var safeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

type Payload struct {
	SchemaVersion int            `json:"schema_version"`
	InstallIDHash string         `json:"install_id_hash"`
	HaspVersion   string         `json:"hasp_version"`
	OS            string         `json:"os"`
	Arch          string         `json:"arch"`
	InstallMethod string         `json:"install_method"`
	PeriodHours   int            `json:"period_hours"`
	Commands24h   int            `json:"commands_24h"`
	CommandsTotal int            `json:"commands_total"`
	TopCommands   []CommandCount `json:"top_root_commands"`
	Setup         Counts         `json:"setup"`
	Features      Counts         `json:"features"`
	Safety        Counts         `json:"safety"`
	Errors        Counts         `json:"errors"`
	Performance   Counts         `json:"performance"`
}

type CommandCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type BuildOptions struct {
	HaspVersion   string
	InstallMethod string
	Now           time.Time
}

func BuildPayload(state State, opts BuildOptions) (Payload, State, error) {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = NowFn()
	}
	if !state.Enabled {
		return Payload{}, state, errors.New("telemetry is disabled")
	}
	if err := ensureInstallID(&state, now); err != nil {
		return Payload{}, state, err
	}
	installMethod := strings.TrimSpace(opts.InstallMethod)
	if installMethod == "" {
		installMethod = "unknown"
	}
	payload := Payload{
		SchemaVersion: SchemaVersion,
		InstallIDHash: InstallHash(state.InstallID, state.InstallYear),
		HaspVersion:   strings.TrimSpace(opts.HaspVersion),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		InstallMethod: installMethod,
		PeriodHours:   defaultPeriodHours,
		Commands24h:   nonNegative(state.Commands24h),
		CommandsTotal: nonNegative(state.CommandsTotal),
		TopCommands:   topRootCommands(state.RootCommands, 10),
		Setup:         state.Setup.cloneAllowed(allowedSetupCounters),
		Features:      state.Features.cloneAllowed(allowedFeatureCounters),
		Safety:        state.Safety.cloneAllowed(allowedSafetyCounters),
		Errors:        state.Errors.cloneAllowed(allowedErrorCounters),
		Performance:   state.Performance.cloneAllowed(allowedPerformanceCounters),
	}
	return payload, state, nil
}

func EncodePayload(payload Payload) ([]byte, error) {
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	data, err := jsonMarshalFn(payload)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ValidatePayload(payload Payload) error {
	if payload.SchemaVersion != SchemaVersion {
		return errors.New("unsupported telemetry schema version")
	}
	if strings.TrimSpace(payload.InstallIDHash) == "" {
		return errors.New("missing telemetry install hash")
	}
	if !safeTokenPattern.MatchString(payload.InstallIDHash) || len(payload.InstallIDHash) != 64 {
		return errors.New("invalid telemetry install hash")
	}
	if !safeTokenPattern.MatchString(payload.HaspVersion) && payload.HaspVersion != "" {
		return errors.New("invalid telemetry version")
	}
	if payload.OS != runtime.GOOS || payload.Arch != runtime.GOARCH {
		return errors.New("invalid telemetry platform")
	}
	if _, ok := allowedInstallMethods[payload.InstallMethod]; !ok {
		return errors.New("invalid telemetry install method")
	}
	for _, command := range payload.TopCommands {
		if _, ok := allowedRootCommands[command.Name]; !ok {
			return errors.New("telemetry payload contains disallowed root command")
		}
		if command.Count <= 0 {
			return errors.New("telemetry payload contains non-positive command count")
		}
	}
	if !countsAllowed(payload.Setup, allowedSetupCounters) ||
		!countsAllowed(payload.Features, allowedFeatureCounters) ||
		!countsAllowed(payload.Safety, allowedSafetyCounters) ||
		!countsAllowed(payload.Errors, allowedErrorCounters) ||
		!countsAllowed(payload.Performance, allowedPerformanceCounters) {
		return errors.New("telemetry payload contains disallowed counter key")
	}
	return nil
}

func topRootCommands(counts Counts, limit int) []CommandCount {
	keys := sortedCountKeys(counts.cloneAllowed(allowedRootCommands))
	out := make([]CommandCount, 0, len(keys))
	for _, key := range keys {
		out = append(out, CommandCount{Name: key, Count: counts[key]})
	}
	// Send the most-used commands, not the alphabetically-first ones (hasp-8xrx).
	// keys is already name-sorted, so a stable sort by descending count yields a
	// deterministic name order within equal counts.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) <= limit {
		return out
	}
	return out[:limit]
}

func countsAllowed(counts Counts, allowed map[string]struct{}) bool {
	for key := range counts {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

var allowedRootCommands = setOf(
	"access", "agent", "app", "approval", "audit", "bootstrap", "check-repo",
	"completion", "config", "daemon", "docs", "export-backup", "import",
	"init", "inject", "lease", "mcp", "ping", "policy", "project", "proof",
	"restore-backup", "run", "secret", "session", "setup", "status",
	"telemetry", "upgrade", "vault", "version", "write-env",
)

var allowedSetupCounters = setOf("started", "completed", "proof_succeeded")
var allowedInstallMethods = setOf("unknown", "source", "homebrew", "release-tarball")

var allowedFeatureCounters = setOf(
	"run", "inject", "write_env", "check_repo", "secret_add", "project_bind",
	"agent_connect", "app_connect", "mcp_started",
)

var allowedSafetyCounters = setOf("redaction_events", "repo_blocks", "audit_verify_failures")

var allowedErrorCounters = setOf(
	"usage", "daemon_unreachable", "vault_locked", "permission_denied",
	"network_timeout", "internal",
)

var allowedPerformanceCounters = setOf("daemon_startup_bucket", "command_duration_bucket")

func setOf(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}
