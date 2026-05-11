package integrations

import (
	"errors"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
)

func TestListProfilesAndDoctorUseClosedTargets(t *testing.T) {
	now := time.Date(2026, 5, 10, 7, 45, 0, 0, time.UTC)
	opts := Options{
		Now: func() time.Time { return now },
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			return []profiles.SupportStatus{{
				Profile: profiles.Profile{
					ID:                   "claude-code",
					Name:                 "Claude Code",
					Transport:            "mcp-stdio",
					Command:              []string{"hasp", "agent", "mcp", "claude-code"},
					ProjectBindingRecipe: "bind project",
					SafeInjectPath:       "inject values",
					WriteEnvPath:         "write env",
				},
				FirstClass: true,
			}}, nil
		},
		SchemaVersion: 1,
	}
	list, err := List(opts)
	if err != nil {
		t.Fatalf("list integrations: %v", err)
	}
	if len(list.Integrations) != 3 {
		t.Fatalf("integrations = %d, want closed target registry of 3", len(list.Integrations))
	}
	profileReply, err := Profiles("mcp", opts)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if len(profileReply.Profiles) != 1 || profileReply.Profiles[0].ID != "claude-code" || profileReply.Profiles[0].Scope != "agent" {
		t.Fatalf("mcp profiles = %+v", profileReply.Profiles)
	}
	doctorReply, err := Doctor("mcp", DoctorRequest{ProfileID: "claude-code"}, opts)
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !doctorReply.OK || doctorReply.RuntimeProbe || doctorReply.DurationMS != 0 || doctorReply.CheckedAt != now {
		t.Fatalf("doctor reply = %+v", doctorReply)
	}
	foundExecutionGuard := false
	for _, check := range doctorReply.Checks {
		if check.Name == "command_execution" && check.OK {
			foundExecutionGuard = true
		}
	}
	if !foundExecutionGuard {
		t.Fatalf("doctor checks missing diagnostic-only guard: %+v", doctorReply.Checks)
	}
	if _, err := Profiles("mcp/bad", opts); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("slash target err = %v, want ErrTargetNotFound", err)
	}
	if _, err := Doctor("mcp", DoctorRequest{ProfileID: "missing"}, opts); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("missing profile err = %v, want ErrProfileNotFound", err)
	}
}

func TestProfileCRUDPersistsAndRequiresVersion(t *testing.T) {
	path := t.TempDir() + "/profiles.json"
	enabled := true
	opts := Options{
		Now:                 func() time.Time { return time.Date(2026, 5, 10, 7, 45, 0, 0, time.UTC) },
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil },
		SchemaVersion:       1,
		ProfileCatalogPath:  path,
	}

	created, err := CreateProfile(ProfileMutationRequest{
		TargetID:      "mcp",
		ID:            "custom-agent",
		Name:          "Custom Agent",
		TargetPattern: "hasp agent mcp custom-agent",
		Scope:         "agent",
		Enabled:       &enabled,
	}, opts)
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}
	if !created.Profile.Managed || created.Profile.Version == "" || created.Profile.TargetID != "mcp" {
		t.Fatalf("created profile = %+v", created.Profile)
	}
	if _, err := CreateProfile(ProfileMutationRequest{
		TargetID:      "mcp",
		ID:            "custom-agent",
		Name:          "Duplicate",
		TargetPattern: "duplicate",
		Scope:         "agent",
	}, opts); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("duplicate err = %v, want ErrProfileConflict", err)
	}

	catalog, err := ProfileCatalog(opts)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(catalog.Profiles) != 1 || catalog.Profiles[0].ID != "custom-agent" {
		t.Fatalf("catalog = %+v", catalog)
	}
	if _, err := UpdateProfile("mcp", "custom-agent", ProfileMutationRequest{
		Name:          "Custom Agent 2",
		TargetPattern: "hasp agent mcp custom-agent-v2",
		Scope:         "agent",
	}, "", opts); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("missing precondition err = %v, want ErrPreconditionRequired", err)
	}
	if _, err := UpdateProfile("mcp", "custom-agent", ProfileMutationRequest{
		Name:          "Custom Agent 2",
		TargetPattern: "hasp agent mcp custom-agent-v2",
		Scope:         "agent",
	}, "stale", opts); !errors.Is(err, ErrProfileVersion) {
		t.Fatalf("stale version err = %v, want ErrProfileVersion", err)
	}

	updated, err := UpdateProfile("mcp", "custom-agent", ProfileMutationRequest{
		Name:          "Custom Agent 2",
		TargetPattern: "hasp agent mcp custom-agent-v2",
		Scope:         "agent",
	}, created.Profile.Version, opts)
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}
	if updated.Profile.Name != "Custom Agent 2" || updated.Profile.Version == created.Profile.Version {
		t.Fatalf("updated profile = %+v", updated.Profile)
	}
	if _, err := DeleteProfile("mcp", "custom-agent", created.Profile.Version, opts); !errors.Is(err, ErrProfileVersion) {
		t.Fatalf("delete stale err = %v, want ErrProfileVersion", err)
	}
	if _, err := DeleteProfile("mcp", "custom-agent", updated.Profile.Version, opts); err != nil {
		t.Fatalf("delete profile: %v", err)
	}
	catalog, err = ProfileCatalog(opts)
	if err != nil {
		t.Fatalf("catalog after delete: %v", err)
	}
	if len(catalog.Profiles) != 0 {
		t.Fatalf("catalog after delete = %+v", catalog)
	}
}
