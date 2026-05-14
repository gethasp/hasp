package integrations

import (
	"errors"
	"os"
	"path/filepath"
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

func TestIntegrationEdgeBranches(t *testing.T) {
	loadErr := errors.New("load statuses")
	if _, err := List(Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, loadErr }}); !errors.Is(err, loadErr) {
		t.Fatalf("list load err = %v, want %v", err, loadErr)
	}
	if _, err := ProfileCatalog(Options{ProfileCatalogPath: t.TempDir()}); err == nil {
		t.Fatal("directory catalog path should fail loading")
	}
	if _, err := Profiles("", Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("blank target err = %v", err)
	}
	if _, err := Profiles("missing", Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("missing target err = %v", err)
	}

	invalidPath := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(invalidPath, []byte(`{`), 0o600); err != nil {
		t.Fatalf("write invalid catalog: %v", err)
	}
	if _, err := List(Options{ProfileCatalogPath: invalidPath, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); err == nil {
		t.Fatal("invalid mutable catalog should fail")
	}

	for _, req := range []ProfileMutationRequest{
		{TargetID: "bad/target", ID: "p", Name: "name", TargetPattern: "cmd", Scope: "agent"},
		{TargetID: "mcp", ID: "bad/id", Name: "name", TargetPattern: "cmd", Scope: "agent"},
		{TargetID: "mcp", ID: "p", TargetPattern: "cmd", Scope: "agent"},
		{TargetID: "mcp", ID: "p", Name: "name", Scope: "agent"},
		{TargetID: "mcp", ID: "p", Name: "name", TargetPattern: "cmd"},
	} {
		if _, err := CreateProfile(req, Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrProfileInvalid) {
			t.Fatalf("create invalid req %+v err = %v, want ErrProfileInvalid", req, err)
		}
	}
	if _, err := CreateProfile(ProfileMutationRequest{TargetID: "missing", ID: "p", Name: "name", TargetPattern: "cmd", Scope: "agent"}, Options{
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil },
	}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("create missing target err = %v", err)
	}
	if _, err := CreateProfile(ProfileMutationRequest{TargetID: "mcp", ID: "p", Name: "name", TargetPattern: "cmd", Scope: "agent"}, Options{
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil },
	}); err == nil {
		t.Fatal("create without mutable catalog path should fail saving")
	}

	immutableOpts := Options{
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			return []profiles.SupportStatus{{Profile: profiles.Profile{ID: "builtin", Name: "Built In", Transport: "mcp", Command: []string{"hasp", "mcp"}}}}, nil
		},
		ProfileCatalogPath: filepath.Join(t.TempDir(), "profiles.json"),
	}
	if _, err := UpdateProfile("mcp", "builtin", ProfileMutationRequest{Name: "x", TargetPattern: "cmd", Scope: "agent"}, "version", immutableOpts); !errors.Is(err, ErrProfileImmutable) {
		t.Fatalf("update immutable err = %v", err)
	}
	if _, err := DeleteProfile("bad/target", "p", "version", immutableOpts); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("delete bad target err = %v", err)
	}
	if _, err := UpdateProfile("mcp", "bad/id", ProfileMutationRequest{Name: "x", TargetPattern: "cmd", Scope: "agent"}, "version", immutableOpts); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("update bad profile id err = %v", err)
	}

	noRuntimeNow := now(Options{})
	if noRuntimeNow.IsZero() {
		t.Fatal("default now returned zero time")
	}
	if schemaVersion(Options{}) != 1 || schemaVersion(Options{SchemaVersion: 7}) != 7 {
		t.Fatal("schema version defaults were not honored")
	}
	if !validID("abc-123_ok") || validID("") || validID("bad/id") {
		t.Fatal("validID edge cases failed")
	}
}

func TestIntegrationResidualBranches(t *testing.T) {
	nowCalls := 0
	reversingNow := func() time.Time {
		nowCalls++
		if nowCalls == 1 {
			return time.Date(2026, 5, 14, 12, 0, 1, 0, time.UTC)
		}
		return time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	}
	opts := Options{
		Now: reversingNow,
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			return []profiles.SupportStatus{
				{Profile: profiles.Profile{ID: "z-shell", Name: "Z Shell", Transport: "stdio", Command: []string{"hasp"}, ProjectBindingRecipe: "project", SafeInjectPath: "env", WriteEnvPath: "shell"}, FirstClass: false},
				{Profile: profiles.Profile{ID: "a-mcp", Name: "A MCP", Transport: "stdio", Command: []string{"hasp", "mcp"}, ProjectBindingRecipe: "project", SafeInjectPath: "env", WriteEnvPath: "shell"}, FirstClass: true},
			}, nil
		},
		SchemaVersion: 9,
	}
	doctor, err := Doctor("mcp", DoctorRequest{}, opts)
	if err != nil {
		t.Fatalf("doctor without profile: %v", err)
	}
	if doctor.DurationMS != 0 || doctor.Schema != 9 {
		t.Fatalf("doctor residual reply = %+v", doctor)
	}
	catalog, err := ProfileCatalog(opts)
	if err != nil {
		t.Fatalf("profile catalog: %v", err)
	}
	if len(catalog.Profiles) < 4 {
		t.Fatalf("catalog profiles = %+v", catalog.Profiles)
	}
	for i := 1; i < len(catalog.Profiles); i++ {
		prev, cur := catalog.Profiles[i-1], catalog.Profiles[i]
		if prev.TargetID > cur.TargetID || (prev.TargetID == cur.TargetID && prev.ID > cur.ID) {
			t.Fatalf("catalog not sorted: %+v", catalog.Profiles)
		}
	}
	list, err := List(opts)
	if err != nil {
		t.Fatalf("list integrations: %v", err)
	}
	var shellStatus string
	for _, target := range list.Integrations {
		if target.ID == "shell-hook" {
			shellStatus = target.Status
		}
	}
	if shellStatus != "degraded" {
		t.Fatalf("shell status = %q", shellStatus)
	}

	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"profiles":[{"target_id":"mcp","id":"legacy","name":"Legacy","target_pattern":"hasp mcp","scope":"agent","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write legacy catalog: %v", err)
	}
	loaded, err := loadMutableCatalog(path)
	if err != nil {
		t.Fatalf("load legacy catalog: %v", err)
	}
	if len(loaded.Profiles) != 1 || !loaded.Profiles[0].Managed || loaded.Profiles[0].Version == "" {
		t.Fatalf("loaded legacy catalog = %+v", loaded)
	}

	blockingParent := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(blockingParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocking parent: %v", err)
	}
	if err := saveMutableCatalog(filepath.Join(blockingParent, "profiles.json"), mutableCatalog{}); err == nil {
		t.Fatal("save catalog under file parent should fail")
	}
	blockingTarget := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.MkdirAll(blockingTarget, 0o700); err != nil {
		t.Fatalf("mkdir blocking target: %v", err)
	}
	if err := saveMutableCatalog(blockingTarget, mutableCatalog{}); err == nil {
		t.Fatal("save catalog over directory should fail")
	}

	loadCalls := 0
	flipErr := errors.New("second load failed")
	_, _, err = mutableProfile("mcp", "missing", Options{
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			loadCalls++
			if loadCalls == 1 {
				return nil, nil
			}
			return nil, flipErr
		},
	})
	if !errors.Is(err, flipErr) {
		t.Fatalf("mutable profile second load err = %v", err)
	}

	validReq := ProfileMutationRequest{TargetID: "mcp", ID: "custom", Name: "Custom", TargetPattern: "hasp mcp", Scope: "agent"}
	dirPath := t.TempDir()
	if _, err := CreateProfile(validReq, Options{ProfileCatalogPath: dirPath, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); err == nil {
		t.Fatal("create should fail when mutable catalog path is a directory")
	}
	if _, err := CreateProfile(ProfileMutationRequest{TargetID: "mcp", ID: "builtin", Name: "Built In", TargetPattern: "hasp mcp", Scope: "agent"}, Options{
		LoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			return []profiles.SupportStatus{{Profile: profiles.Profile{ID: "builtin", Name: "Built In", Transport: "mcp", Command: []string{"hasp", "mcp"}}}}, nil
		},
	}); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("create built-in conflict err = %v", err)
	}
	pathForFailures := filepath.Join(t.TempDir(), "profiles.json")
	created, err := CreateProfile(validReq, Options{ProfileCatalogPath: pathForFailures, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }})
	if err != nil {
		t.Fatalf("create for failure setup: %v", err)
	}
	blockingSaveParent := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(blockingSaveParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocking save parent: %v", err)
	}
	saveFailOpts := Options{ProfileCatalogPath: filepath.Join(blockingSaveParent, "profiles.json"), LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}
	if _, err := UpdateProfile("mcp", "custom", ProfileMutationRequest{Name: "Custom 2", TargetPattern: "hasp mcp", Scope: "agent"}, created.Profile.Version, saveFailOpts); err == nil {
		t.Fatal("update should fail when saving mutable catalog fails")
	}
	if _, err := UpdateProfile("bad/target", "custom", ProfileMutationRequest{Name: "Custom 2", TargetPattern: "hasp mcp", Scope: "agent"}, created.Profile.Version, Options{}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("update bad target err = %v", err)
	}
	if _, err := UpdateProfile("mcp", "custom", ProfileMutationRequest{Name: "", TargetPattern: "hasp mcp", Scope: "agent"}, created.Profile.Version, Options{ProfileCatalogPath: pathForFailures, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrProfileInvalid) {
		t.Fatalf("update invalid request err = %v", err)
	}
	if _, err := UpdateProfile("mcp", "custom", ProfileMutationRequest{Name: "Custom 2", TargetPattern: "hasp mcp", Scope: "agent"}, created.Profile.Version, Options{ProfileCatalogPath: t.TempDir(), LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); err == nil {
		t.Fatal("update should fail when loading mutable catalog fails")
	}
	if _, err := DeleteProfile("mcp", "custom", "", Options{}); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("delete missing precondition err = %v", err)
	}
	if _, err := DeleteProfile("mcp", "custom", created.Profile.Version, saveFailOpts); err == nil {
		t.Fatal("delete should fail when saving mutable catalog fails")
	}
	if _, err := Doctor("missing", DoctorRequest{}, Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("doctor missing target err = %v", err)
	}
	unknownCatalog := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(unknownCatalog, []byte(`{"profiles":[{"target_id":"unknown","id":"p","name":"P","target_pattern":"x","scope":"agent","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write unknown mutable catalog: %v", err)
	}
	if _, err := List(Options{ProfileCatalogPath: unknownCatalog, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); err != nil {
		t.Fatalf("list with unknown mutable profile should ignore it: %v", err)
	}
	if _, _, err := mutableProfile("mcp", "missing", Options{LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("mutable missing profile err = %v", err)
	}

	lockedDir := t.TempDir()
	lockedPath := filepath.Join(lockedDir, "profiles.json")
	if err := os.WriteFile(lockedPath, []byte(`{"profiles":[{"target_id":"mcp","id":"custom","name":"Custom","target_pattern":"hasp mcp","scope":"agent","enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write locked catalog: %v", err)
	}
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Fatalf("chmod locked dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockedDir, 0o700) })
	lockedOpts := Options{ProfileCatalogPath: lockedPath, LoadSupportStatuses: func() ([]profiles.SupportStatus, error) { return nil, nil }}
	loadedForLock, err := loadMutableCatalog(lockedPath)
	if err != nil {
		t.Fatalf("load locked setup catalog: %v", err)
	}
	if _, err := UpdateProfile("mcp", "custom", ProfileMutationRequest{Name: "Custom 2", TargetPattern: "hasp mcp", Scope: "agent"}, loadedForLock.Profiles[0].Version, lockedOpts); err == nil {
		t.Fatal("update should fail writing into locked catalog directory")
	}
	if _, err := DeleteProfile("mcp", "custom", loadedForLock.Profiles[0].Version, lockedOpts); err == nil {
		t.Fatal("delete should fail writing into locked catalog directory")
	}
}

func TestContainsToken(t *testing.T) {
	if !containsToken([]string{"alpha", "beta"}, "beta") {
		t.Fatal("expected token match")
	}
	if containsToken([]string{"alpha", "beta"}, "gamma") {
		t.Fatal("unexpected token match")
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
