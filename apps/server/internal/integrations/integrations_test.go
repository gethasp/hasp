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
	if !doctorReply.OK || doctorReply.DurationMS != 0 || doctorReply.CheckedAt != now {
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
