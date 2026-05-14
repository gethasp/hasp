package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
)

var (
	ErrTargetNotFound       = errors.New("integration target not found")
	ErrProfileNotFound      = errors.New("integration profile not found")
	ErrProfileConflict      = errors.New("integration profile already exists")
	ErrProfileImmutable     = errors.New("integration profile is immutable")
	ErrProfileInvalid       = errors.New("integration profile is invalid")
	ErrProfileVersion       = errors.New("integration profile version mismatch")
	ErrPreconditionRequired = errors.New("integration profile precondition required")
)

type Profile struct {
	ID            string `json:"id"`
	TargetID      string `json:"target_id,omitempty"`
	Name          string `json:"name"`
	TargetPattern string `json:"target_pattern"`
	Scope         string `json:"scope"`
	Enabled       bool   `json:"enabled"`
	Version       string `json:"version,omitempty"`
	Managed       bool   `json:"managed,omitempty"`
}

type Integration struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	LastCheckedAt time.Time `json:"last_checked_at"`
	Profiles      []Profile `json:"profiles"`
}

type ListResponse struct {
	Schema       int           `json:"_schema"`
	Integrations []Integration `json:"integrations"`
}

type ProfilesResponse struct {
	Schema   int       `json:"_schema"`
	Profiles []Profile `json:"profiles"`
}

type ProfileMutationRequest struct {
	TargetID      string `json:"target_id,omitempty"`
	ID            string `json:"id,omitempty"`
	Name          string `json:"name"`
	TargetPattern string `json:"target_pattern"`
	Scope         string `json:"scope"`
	Enabled       *bool  `json:"enabled,omitempty"`
}

type ProfileMutationResponse struct {
	Schema  int     `json:"_schema"`
	Profile Profile `json:"profile"`
}

type DoctorRequest struct {
	ProfileID string `json:"profile_id,omitempty"`
}

type DoctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	FixHint string `json:"fix_hint,omitempty"`
}

type DoctorResponse struct {
	Schema       int           `json:"_schema"`
	TargetID     string        `json:"target_id"`
	ProfileID    string        `json:"profile_id,omitempty"`
	OK           bool          `json:"ok"`
	RuntimeProbe bool          `json:"runtime_probe"`
	Checks       []DoctorCheck `json:"checks"`
	DurationMS   int           `json:"duration_ms"`
	CheckedAt    time.Time     `json:"checked_at"`
}

type Options struct {
	Now                 func() time.Time
	LoadSupportStatuses func() ([]profiles.SupportStatus, error)
	SchemaVersion       int
	ProfileCatalogPath  string
}

func List(opts Options) (ListResponse, error) {
	targets, err := buildTargets(opts)
	if err != nil {
		return ListResponse{}, err
	}
	return ListResponse{Schema: schemaVersion(opts), Integrations: targets}, nil
}

func Profiles(targetID string, opts Options) (ProfilesResponse, error) {
	target, err := findTarget(targetID, opts)
	if err != nil {
		return ProfilesResponse{}, err
	}
	return ProfilesResponse{Schema: schemaVersion(opts), Profiles: target.Profiles}, nil
}

func ProfileCatalog(opts Options) (ProfilesResponse, error) {
	targets, err := buildTargets(opts)
	if err != nil {
		return ProfilesResponse{}, err
	}
	var out []Profile
	for _, target := range targets {
		out = append(out, target.Profiles...)
	}
	slices.SortFunc(out, func(a, b Profile) int {
		if cmp := strings.Compare(a.TargetID, b.TargetID); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
	return ProfilesResponse{Schema: schemaVersion(opts), Profiles: out}, nil
}

func CreateProfile(req ProfileMutationRequest, opts Options) (ProfileMutationResponse, error) {
	profile, err := normalizeProfileRequest(req, "")
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	target, err := findTarget(profile.TargetID, Options{
		Now:                 opts.Now,
		LoadSupportStatuses: opts.LoadSupportStatuses,
		SchemaVersion:       opts.SchemaVersion,
	})
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	if _, found := targetProfile(target, profile.ID); found {
		return ProfileMutationResponse{}, fmt.Errorf("%w: %s", ErrProfileConflict, profile.ID)
	}
	catalog, err := loadMutableCatalog(opts.ProfileCatalogPath)
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	for _, existing := range catalog.Profiles {
		if existing.TargetID == profile.TargetID && existing.ID == profile.ID {
			return ProfileMutationResponse{}, fmt.Errorf("%w: %s", ErrProfileConflict, profile.ID)
		}
	}
	profile.Managed = true
	profile.Version = profileVersion(profile)
	catalog.Profiles = append(catalog.Profiles, profile)
	if err := saveMutableCatalog(opts.ProfileCatalogPath, catalog); err != nil {
		return ProfileMutationResponse{}, err
	}
	return ProfileMutationResponse{Schema: schemaVersion(opts), Profile: profile}, nil
}

func UpdateProfile(targetID string, profileID string, req ProfileMutationRequest, ifMatch string, opts Options) (ProfileMutationResponse, error) {
	if strings.TrimSpace(ifMatch) == "" {
		return ProfileMutationResponse{}, ErrPreconditionRequired
	}
	targetID = strings.TrimSpace(targetID)
	profileID = strings.TrimSpace(profileID)
	if !validID(targetID) {
		return ProfileMutationResponse{}, fmt.Errorf("%w: %s", ErrTargetNotFound, targetID)
	}
	if !validID(profileID) {
		return ProfileMutationResponse{}, fmt.Errorf("%w: %s", ErrProfileNotFound, profileID)
	}
	catalog, idx, err := mutableProfile(targetID, profileID, opts)
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	if catalog.Profiles[idx].Version != strings.TrimSpace(ifMatch) {
		return ProfileMutationResponse{}, ErrProfileVersion
	}
	req.TargetID = targetID
	req.ID = profileID
	next, err := normalizeProfileRequest(req, catalog.Profiles[idx].Version)
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	next.Managed = true
	next.Version = profileVersion(next)
	catalog.Profiles[idx] = next
	if err := saveMutableCatalog(opts.ProfileCatalogPath, catalog); err != nil {
		return ProfileMutationResponse{}, err
	}
	return ProfileMutationResponse{Schema: schemaVersion(opts), Profile: next}, nil
}

func DeleteProfile(targetID string, profileID string, ifMatch string, opts Options) (ProfileMutationResponse, error) {
	if strings.TrimSpace(ifMatch) == "" {
		return ProfileMutationResponse{}, ErrPreconditionRequired
	}
	catalog, idx, err := mutableProfile(strings.TrimSpace(targetID), strings.TrimSpace(profileID), opts)
	if err != nil {
		return ProfileMutationResponse{}, err
	}
	removed := catalog.Profiles[idx]
	if removed.Version != strings.TrimSpace(ifMatch) {
		return ProfileMutationResponse{}, ErrProfileVersion
	}
	catalog.Profiles = append(catalog.Profiles[:idx], catalog.Profiles[idx+1:]...)
	if err := saveMutableCatalog(opts.ProfileCatalogPath, catalog); err != nil {
		return ProfileMutationResponse{}, err
	}
	return ProfileMutationResponse{Schema: schemaVersion(opts), Profile: removed}, nil
}

func Doctor(targetID string, req DoctorRequest, opts Options) (DoctorResponse, error) {
	started := now(opts)
	target, err := findTarget(targetID, opts)
	if err != nil {
		return DoctorResponse{}, err
	}
	profileID := strings.TrimSpace(req.ProfileID)
	checks := []DoctorCheck{{
		Name:    "target_catalog",
		OK:      true,
		Message: fmt.Sprintf("%s integration target is available", target.ID),
	}}
	if profileID == "" {
		checks = append(checks, DoctorCheck{
			Name:    "profile_scope",
			OK:      true,
			Message: fmt.Sprintf("%d profiles available for this target", len(target.Profiles)),
		})
	} else {
		profile, ok := targetProfile(target, profileID)
		if !ok {
			return DoctorResponse{}, fmt.Errorf("%w: %s", ErrProfileNotFound, profileID)
		}
		checks = append(checks, DoctorCheck{
			Name:    "profile_scope",
			OK:      true,
			Message: fmt.Sprintf("profile %s is available for %s", profile.ID, target.ID),
		})
	}
	checks = append(checks,
		DoctorCheck{Name: "command_execution", OK: true, Message: "doctor is diagnostic-only and did not execute profile commands"},
		DoctorCheck{Name: "secret_exposure", OK: true, Message: "doctor returned metadata only; no secret values are included"},
	)
	duration := int(now(opts).Sub(started).Milliseconds())
	if duration < 0 {
		duration = 0
	}
	return DoctorResponse{
		Schema:       schemaVersion(opts),
		TargetID:     target.ID,
		ProfileID:    profileID,
		OK:           true,
		RuntimeProbe: false,
		Checks:       checks,
		DurationMS:   duration,
		CheckedAt:    started,
	}, nil
}

func findTarget(targetID string, opts Options) (Integration, error) {
	targetID = strings.TrimSpace(targetID)
	if !validID(targetID) {
		return Integration{}, fmt.Errorf("%w: %s", ErrTargetNotFound, targetID)
	}
	targets, err := buildTargets(opts)
	if err != nil {
		return Integration{}, err
	}
	for _, target := range targets {
		if target.ID == targetID {
			return target, nil
		}
	}
	return Integration{}, fmt.Errorf("%w: %s", ErrTargetNotFound, targetID)
}

func buildTargets(opts Options) ([]Integration, error) {
	load := opts.LoadSupportStatuses
	if load == nil {
		load = profiles.LoadSupportStatuses
	}
	statuses, err := load()
	if err != nil {
		return nil, err
	}
	checkedAt := now(opts)
	targets := []Integration{
		{ID: "env-injection", Name: "Environment Injection", Kind: "env-injection", Status: "ok", LastCheckedAt: checkedAt},
		{ID: "mcp", Name: "MCP", Kind: "mcp", Status: "ok", LastCheckedAt: checkedAt},
		{ID: "shell-hook", Name: "Shell Hook", Kind: "shell-hook", Status: "ok", LastCheckedAt: checkedAt},
	}
	for _, status := range statuses {
		for _, targetID := range targetIDsForProfile(status.Profile) {
			idx := slices.IndexFunc(targets, func(target Integration) bool { return target.ID == targetID })
			targets[idx].Profiles = append(targets[idx].Profiles, profileView(status.Profile, targetID))
			if !status.FirstClass && targets[idx].Status == "ok" {
				targets[idx].Status = "degraded"
			}
		}
	}
	mutable, err := loadMutableCatalog(opts.ProfileCatalogPath)
	if err != nil {
		return nil, err
	}
	for _, profile := range mutable.Profiles {
		idx := slices.IndexFunc(targets, func(target Integration) bool { return target.ID == profile.TargetID })
		if idx < 0 {
			continue
		}
		targets[idx].Profiles = append(targets[idx].Profiles, profile)
	}
	for i := range targets {
		slices.SortFunc(targets[i].Profiles, func(a, b Profile) int { return strings.Compare(a.ID, b.ID) })
	}
	return targets, nil
}

func targetIDsForProfile(profile profiles.Profile) []string {
	ids := []string{"env-injection", "shell-hook"}
	if strings.Contains(profile.Transport, "mcp") || containsToken(profile.Command, "mcp") {
		ids = append(ids, "mcp")
	}
	return ids
}

func profileView(profile profiles.Profile, targetID string) Profile {
	scope := "project"
	pattern := profile.ProjectBindingRecipe
	switch targetID {
	case "env-injection":
		scope = "process"
		pattern = profile.SafeInjectPath
	case "mcp":
		scope = "agent"
		pattern = strings.Join(profile.Command, " ")
	case "shell-hook":
		scope = "shell"
		pattern = profile.WriteEnvPath
	}
	out := Profile{ID: profile.ID, TargetID: targetID, Name: profile.Name, TargetPattern: pattern, Scope: scope, Enabled: true}
	out.Version = profileVersion(out)
	return out
}

func targetProfile(target Integration, profileID string) (Profile, bool) {
	for _, profile := range target.Profiles {
		if profile.ID == profileID {
			return profile, true
		}
	}
	return Profile{}, false
}

func containsToken(values []string, token string) bool {
	for _, value := range values {
		if value == token {
			return true
		}
	}
	return false
}

func validID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

type mutableCatalog struct {
	Profiles []Profile `json:"profiles"`
}

func findAnyProfile(targetID string, profileID string, opts Options) (Profile, bool, error) {
	target, err := findTarget(targetID, opts)
	if err != nil {
		return Profile{}, false, err
	}
	profile, ok := targetProfile(target, profileID)
	return profile, ok, nil
}

func mutableProfile(targetID string, profileID string, opts Options) (mutableCatalog, int, error) {
	if _, err := findTarget(targetID, Options{
		Now:                 opts.Now,
		LoadSupportStatuses: opts.LoadSupportStatuses,
		SchemaVersion:       opts.SchemaVersion,
	}); err != nil {
		return mutableCatalog{}, -1, err
	}
	catalog, err := loadMutableCatalog(opts.ProfileCatalogPath)
	if err != nil {
		return mutableCatalog{}, -1, err
	}
	for idx, profile := range catalog.Profiles {
		if profile.TargetID == targetID && profile.ID == profileID {
			return catalog, idx, nil
		}
	}
	if _, found, err := findAnyProfile(targetID, profileID, Options{
		Now:                 opts.Now,
		LoadSupportStatuses: opts.LoadSupportStatuses,
		SchemaVersion:       opts.SchemaVersion,
	}); err != nil {
		return mutableCatalog{}, -1, err
	} else if found {
		return mutableCatalog{}, -1, fmt.Errorf("%w: %s", ErrProfileImmutable, profileID)
	}
	return mutableCatalog{}, -1, fmt.Errorf("%w: %s", ErrProfileNotFound, profileID)
}

func normalizeProfileRequest(req ProfileMutationRequest, currentVersion string) (Profile, error) {
	targetID := strings.TrimSpace(req.TargetID)
	profileID := strings.TrimSpace(req.ID)
	if !validID(targetID) {
		return Profile{}, fmt.Errorf("%w: target_id", ErrProfileInvalid)
	}
	if !validID(profileID) {
		return Profile{}, fmt.Errorf("%w: id", ErrProfileInvalid)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return Profile{}, fmt.Errorf("%w: name", ErrProfileInvalid)
	}
	pattern := strings.TrimSpace(req.TargetPattern)
	if pattern == "" {
		return Profile{}, fmt.Errorf("%w: target_pattern", ErrProfileInvalid)
	}
	scope := strings.TrimSpace(req.Scope)
	if scope == "" {
		return Profile{}, fmt.Errorf("%w: scope", ErrProfileInvalid)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return Profile{ID: profileID, TargetID: targetID, Name: name, TargetPattern: pattern, Scope: scope, Enabled: enabled, Version: currentVersion}, nil
}

func loadMutableCatalog(path string) (mutableCatalog, error) {
	if strings.TrimSpace(path) == "" {
		return mutableCatalog{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return mutableCatalog{}, nil
	}
	if err != nil {
		return mutableCatalog{}, err
	}
	var catalog mutableCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return mutableCatalog{}, err
	}
	for idx := range catalog.Profiles {
		catalog.Profiles[idx].Managed = true
		if catalog.Profiles[idx].Version == "" {
			catalog.Profiles[idx].Version = profileVersion(catalog.Profiles[idx])
		}
	}
	return catalog, nil
}

func saveMutableCatalog(path string, catalog mutableCatalog) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("profile catalog path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(catalog, "", "  ")
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func profileVersion(profile Profile) string {
	payload := struct {
		ID            string `json:"id"`
		TargetID      string `json:"target_id"`
		Name          string `json:"name"`
		TargetPattern string `json:"target_pattern"`
		Scope         string `json:"scope"`
		Enabled       bool   `json:"enabled"`
	}{profile.ID, profile.TargetID, profile.Name, profile.TargetPattern, profile.Scope, profile.Enabled}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

func now(opts Options) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

func schemaVersion(opts Options) int {
	if opts.SchemaVersion != 0 {
		return opts.SchemaVersion
	}
	return 1
}
