package integrations

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
)

var (
	ErrTargetNotFound  = errors.New("integration target not found")
	ErrProfileNotFound = errors.New("integration profile not found")
)

type Profile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	TargetPattern string `json:"target_pattern"`
	Scope         string `json:"scope"`
	Enabled       bool   `json:"enabled"`
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
	Schema     int           `json:"_schema"`
	TargetID   string        `json:"target_id"`
	ProfileID  string        `json:"profile_id,omitempty"`
	OK         bool          `json:"ok"`
	Checks     []DoctorCheck `json:"checks"`
	DurationMS int           `json:"duration_ms"`
	CheckedAt  time.Time     `json:"checked_at"`
}

type Options struct {
	Now                 func() time.Time
	LoadSupportStatuses func() ([]profiles.SupportStatus, error)
	SchemaVersion       int
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
	ok := true
	for _, check := range checks {
		if !check.OK {
			ok = false
			break
		}
	}
	duration := int(now(opts).Sub(started).Milliseconds())
	if duration < 0 {
		duration = 0
	}
	return DoctorResponse{
		Schema:     schemaVersion(opts),
		TargetID:   target.ID,
		ProfileID:  profileID,
		OK:         ok,
		Checks:     checks,
		DurationMS: duration,
		CheckedAt:  started,
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
			if idx < 0 {
				continue
			}
			targets[idx].Profiles = append(targets[idx].Profiles, profileView(status.Profile, targetID))
			if !status.FirstClass && targets[idx].Status == "ok" {
				targets[idx].Status = "degraded"
			}
		}
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
	return Profile{ID: profile.ID, Name: profile.Name, TargetPattern: pattern, Scope: scope, Enabled: true}
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
