package telemetry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

const (
	SchemaVersion = 1

	EnvDisabled = "HASP_TELEMETRY_DISABLED"

	defaultPeriodHours = 24
	erasureHashTTL     = 400 * 24 * time.Hour
	idContext          = "hasp-cli-telemetry-v1"
)

var (
	ErrDisabledByEnv = errors.New("telemetry blocked by HASP_TELEMETRY_DISABLED")

	StatePathFn = paths.TelemetryStatePath
	NowFn       = func() time.Time { return time.Now().UTC() }
	RandomFn    = rand.Read

	readFileFn  = os.ReadFile
	writeFileFn = os.WriteFile
	mkdirAllFn  = os.MkdirAll
	removeFn    = os.Remove
)

type Store struct {
	Path string
}

func DefaultStore() Store {
	return Store{}
}

func (s Store) statePath() (string, error) {
	if strings.TrimSpace(s.Path) != "" {
		return s.Path, nil
	}
	if testing.Testing() || os.Getenv(paths.EnvTest) == "1" {
		if path := strings.TrimSpace(os.Getenv("HASP_TELEMETRY_TEST_STATE")); path != "" {
			return path, nil
		}
		return "", errors.New("telemetry state path must be explicit in test contexts")
	}
	return StatePathFn()
}

type State struct {
	Enabled       bool        `json:"enabled"`
	ConsentAt     time.Time   `json:"consent_at,omitempty"`
	InstallID     string      `json:"install_id,omitempty"`
	InstallYear   int         `json:"install_year,omitempty"`
	LastPingAt    time.Time   `json:"last_ping_at,omitempty"`
	Commands24h   int         `json:"commands_24h,omitempty"`
	CommandsTotal int         `json:"commands_total,omitempty"`
	RootCommands  Counts      `json:"root_commands,omitempty"`
	Setup         Counts      `json:"setup,omitempty"`
	Features      Counts      `json:"features,omitempty"`
	Safety        Counts      `json:"safety,omitempty"`
	Errors        Counts      `json:"errors,omitempty"`
	Performance   Counts      `json:"performance,omitempty"`
	ErasureIDs    []ErasureID `json:"erasure_ids,omitempty"`
}

type Counts map[string]int

type ErasureID struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c Counts) cloneAllowed(allowed map[string]struct{}) Counts {
	out := Counts{}
	for key, value := range c {
		key = strings.TrimSpace(key)
		if value <= 0 {
			continue
		}
		if _, ok := allowed[key]; ok {
			out[key] = value
		}
	}
	return out
}

func (s Store) Load() (State, error) {
	path, err := s.statePath()
	if err != nil {
		return State{}, err
	}
	data, err := readFileFn(path)
	if errors.Is(err, os.ErrNotExist) {
		return emptyState(), nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return emptyState(), nil
	}
	normalizeState(&state)
	return state, nil
}

func (s Store) Save(state State) error {
	path, err := s.statePath()
	if err != nil {
		return err
	}
	normalizeState(&state)
	if err := mkdirAllFn(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileFn(path, data, 0o600)
}

func (s Store) Enable(now time.Time) (State, error) {
	if DisabledByEnv() {
		return State{}, ErrDisabledByEnv
	}
	state, err := s.Load()
	if err != nil {
		return State{}, err
	}
	state.Enabled = true
	state.ConsentAt = now.UTC()
	if err := ensureInstallID(&state, now.UTC()); err != nil {
		return State{}, err
	}
	if err := s.Save(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s Store) Disable() (State, error) {
	state, err := s.Load()
	if err != nil {
		return State{}, err
	}
	state.Enabled = false
	if err := s.Save(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s Store) Forget() ([]string, error) {
	state, err := s.Load()
	if err != nil {
		return nil, err
	}
	hashes := []string{}
	if strings.TrimSpace(state.InstallID) != "" && state.InstallYear > 0 {
		hashes = append(hashes, InstallHash(state.InstallID, state.InstallYear))
	}
	for _, prior := range state.ErasureIDs {
		if strings.TrimSpace(prior.Hash) != "" {
			hashes = append(hashes, strings.TrimSpace(prior.Hash))
		}
	}
	path, err := s.statePath()
	if err != nil {
		return dedupeStrings(hashes), err
	}
	if err := removeFn(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return dedupeStrings(hashes), err
	}
	return dedupeStrings(hashes), nil
}

func (s Store) RecordRootCommand(root string, now time.Time) error {
	if DisabledByEnv() {
		return nil
	}
	state, err := s.Load()
	if err != nil || !state.Enabled {
		return nil
	}
	root = strings.TrimSpace(root)
	if _, ok := allowedRootCommands[root]; !ok {
		return nil
	}
	state.Commands24h++
	state.CommandsTotal++
	if state.RootCommands == nil {
		state.RootCommands = Counts{}
	}
	state.RootCommands[root]++
	if err := ensureInstallID(&state, now.UTC()); err != nil {
		return nil
	}
	_ = s.Save(state)
	return nil
}

func DisabledByEnv() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(EnvDisabled)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func ensureInstallID(state *State, now time.Time) error {
	year := now.UTC().Year()
	if state.InstallID != "" && state.InstallYear == year {
		return nil
	}
	if state.InstallID != "" && state.InstallYear > 0 {
		state.ErasureIDs = append(state.ErasureIDs, ErasureID{
			Hash:      InstallHash(state.InstallID, state.InstallYear),
			ExpiresAt: now.UTC().Add(erasureHashTTL),
		})
	}
	raw := make([]byte, 32)
	if _, err := RandomFn(raw); err != nil {
		return fmt.Errorf("generate telemetry install id: %w", err)
	}
	state.InstallID = hex.EncodeToString(raw)
	state.InstallYear = year
	return nil
}

func InstallHash(installID string, year int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", idContext, installID, year)))
	return hex.EncodeToString(sum[:])
}

func emptyState() State {
	return State{
		RootCommands: Counts{},
		Setup:        Counts{},
		Features:     Counts{},
		Safety:       Counts{},
		Errors:       Counts{},
		Performance:  Counts{},
	}
}

func normalizeState(state *State) {
	if state.RootCommands == nil {
		state.RootCommands = Counts{}
	}
	if state.Setup == nil {
		state.Setup = Counts{}
	}
	if state.Features == nil {
		state.Features = Counts{}
	}
	if state.Safety == nil {
		state.Safety = Counts{}
	}
	if state.Errors == nil {
		state.Errors = Counts{}
	}
	if state.Performance == nil {
		state.Performance = Counts{}
	}
	state.InstallID = strings.TrimSpace(state.InstallID)
	now := NowFn()
	filtered := state.ErasureIDs[:0]
	for _, id := range state.ErasureIDs {
		id.Hash = strings.TrimSpace(id.Hash)
		if id.Hash == "" {
			continue
		}
		if !id.ExpiresAt.IsZero() && id.ExpiresAt.Before(now) {
			continue
		}
		filtered = append(filtered, id)
	}
	state.ErasureIDs = filtered
}

func sortedCountKeys(counts Counts) []string {
	keys := make([]string, 0, len(counts))
	for key, value := range counts {
		if value > 0 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
