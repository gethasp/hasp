package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadRepoManifestRejectsUnsupportedVersion(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v2",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}]
}`)
}

func TestLoadRepoManifestRejectsDuplicateTargetNames(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": ".", "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]},
    {"name": "server.dev", "root": ".", "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsUnsafeTargetNames(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "web/dev", "root": ".", "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsUnknownRequirementRefsInDelivery(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "secret_02", "item": "DATABASE_URL"}
  ],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": ".", "delivery": [{"as": "env", "name": "DATABASE_URL", "ref": "@DATABASE_URL"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsUnknownRequirementKinds(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "token", "classification": "secret", "required": true}]
}`)
}

func TestLoadRepoManifestRejectsUnknownRequirementClassifications(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "internal", "required": true}]
}`)
}

func TestLoadRepoManifestRejectsBrowserSessionDelivery(t *testing.T) {
	projectRoot := t.TempDir()
	if _, err := DecodeRepoManifest(projectRoot, []byte(`{
  "version": "v1",
  "references": [{"alias": "session_01", "item": "BROWSER_SESSION"}],
  "requirements": [{"ref": "session_01", "kind": "kv", "classification": "browser_session", "required": true}]
}`)); err != nil {
		t.Fatalf("browser-session requirement declaration should remain value-free: %v", err)
	}

	_, err := DecodeRepoManifest(projectRoot, []byte(`{
  "version": "v1",
  "references": [{"alias": "session_01", "item": "BROWSER_SESSION"}],
  "requirements": [{"ref": "session_01", "kind": "kv", "classification": "browser_session", "required": true}],
  "targets": [
    {"name": "browser.dev", "delivery": [{"as": "env", "name": "BROWSER_SESSION", "ref": "session_01"}]}
  ]
}`))
	if err == nil || !strings.Contains(err.Error(), "requires an explicit high-risk capability path") {
		t.Fatalf("expected browser-session delivery rejection, got %v", err)
	}
}

func TestRepoManifestRejectsBrowserSessionValueFields(t *testing.T) {
	for _, body := range []string{
		`{"version":"v1","references":[],"cookies":[]}`,
		`{"version":"v1","references":[],"localStorage":{}}`,
		`{"version":"v1","references":[],"sessionStorage":{}}`,
		`{"version":"v1","references":[],"indexedDB":{}}`,
		`{"version":"v1","references":[],"browserSession":{}}`,
		`{"version":"v1","references":[],"browserSessionState":{}}`,
		`{"version":"v1","references":[],"browser_session_state":{}}`,
	} {
		if _, err := DecodeRepoManifest(t.TempDir(), []byte(body)); err == nil {
			t.Fatalf("expected browser/session value field rejection for %s", body)
		}
	}
}

func TestLoadRepoManifestRejectsUnknownDeliveryFormats(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": ".", "delivery": [{"as": "dotenv", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsShellStringCommands(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {
      "name": "server.dev",
      "root": ".",
      "command": "pnpm dev",
      "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]
    }
  ]
}`)
}

func TestLoadRepoManifestRejectsDangerousEnvNames(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": ".", "delivery": [{"as": "env", "name": "PATH", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsTargetRootPathTraversal(t *testing.T) {
	assertLoadRepoManifestRejected(t, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": "../outside", "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)
}

func TestLoadRepoManifestRejectsTargetRootSymlinkEscapes(t *testing.T) {
	projectRoot := t.TempDir()
	outsideDir := t.TempDir()
	linkPath := filepath.Join(projectRoot, "escape-link")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink setup unavailable: %v", err)
	}
	writeRepoManifestForTest(t, projectRoot, `{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {"name": "server.dev", "root": "escape-link", "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]}
  ]
}`)

	assertLoadRepoManifestRejectedAtRoot(t, projectRoot)
}

func TestLoadRepoManifestRejectsOutputPathThroughSymlinkParent(t *testing.T) {
	projectRoot := t.TempDir()
	outsideDir := t.TempDir()
	linkPath := filepath.Join(projectRoot, "linked-output")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink setup unavailable: %v", err)
	}
	writeRepoManifestForTest(t, projectRoot, `{
  "version": "v1",
  "references": [{"alias": "config_01", "item": "API_BASE_URL"}],
  "requirements": [{"ref": "@API_BASE_URL", "kind": "kv", "classification": "public_config", "required": true}],
  "targets": [
    {
      "name": "build.config",
      "root": ".",
      "delivery": [{"as": "xcconfig", "name": "API_BASE_URL", "ref": "@API_BASE_URL", "output": "linked-output/Secrets.generated.xcconfig"}]
    }
  ]
}`)

	assertLoadRepoManifestRejectedAtRoot(t, projectRoot)
}

func TestLoadRepoManifestDoesNotExecuteTargetCommands(t *testing.T) {
	projectRoot := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "manifest-command-ran")
	writeRepoManifestForTest(t, projectRoot, fmt.Sprintf(`{
  "version": "v1",
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {
      "name": "server.dev",
      "root": ".",
      "command": ["sh", "-c", "touch %s"],
      "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]
    }
  ]
}`, sentinel))

	if _, err := LoadRepoManifest(projectRoot); err != nil {
		t.Fatalf("manifest parse should stay read-only, got %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("manifest parsing executed a target command and created %s", sentinel)
	}
}

func TestManifestTargetReviewDetectsChangedCommandRefsOutputsAndDelivery(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	projectRoot := t.TempDir()
	base := ManifestTargetExpansion{
		TargetName:   "server.dev",
		TargetRoot:   "apps/server",
		ManifestHash: "hash-1",
		Command:      []string{"npm", "run", "dev"},
		Env:          map[string]string{"OPENAI_API_KEY": "secret_01"},
		Files:        map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "file_01"},
		XCConfig:     map[string]string{"API_BASE_URL": "config_01"},
		Outputs:      map[string]string{"API_BASE_URL": "apps/server/Config/Secrets.generated.xcconfig"},
		Refs:         []string{"config_01", "secret_01"},
		Destinations: []string{"API_BASE_URL", "OPENAI_API_KEY"},
	}
	if drift, err := handle.ManifestTargetDrift(projectRoot, base); err != nil {
		t.Fatalf("first drift check: %v", err)
	} else if drift.Known || drift.Changed {
		t.Fatalf("new target should not be marked drifted: %+v", drift)
	}
	if err := handle.RecordManifestTargetReview(projectRoot, base); err != nil {
		t.Fatalf("record review: %v", err)
	}

	for _, tc := range []struct {
		name         string
		expansion    ManifestTargetExpansion
		wantCommand  bool
		wantRefs     bool
		wantDelivery bool
		wantOutputs  bool
	}{
		{
			name:        "command",
			expansion:   manifestExpansionCopy(base, func(e *ManifestTargetExpansion) { e.Command = []string{"npm", "test"} }),
			wantCommand: true,
		},
		{
			name: "refs",
			expansion: manifestExpansionCopy(base, func(e *ManifestTargetExpansion) {
				e.Env["OPENAI_API_KEY"] = "secret_02"
				e.Refs = []string{"config_01", "secret_02"}
			}),
			wantRefs:     true,
			wantDelivery: true,
		},
		{
			name: "delivery",
			expansion: manifestExpansionCopy(base, func(e *ManifestTargetExpansion) {
				e.Env["DATABASE_URL"] = "secret_01"
				e.Destinations = []string{"API_BASE_URL", "DATABASE_URL", "OPENAI_API_KEY"}
			}),
			wantDelivery: true,
		},
		{
			name: "outputs",
			expansion: manifestExpansionCopy(base, func(e *ManifestTargetExpansion) {
				e.Outputs["API_BASE_URL"] = "apps/server/Config/Other.generated.xcconfig"
			}),
			wantOutputs: true,
		},
	} {
		drift, err := handle.ManifestTargetDrift(projectRoot, tc.expansion)
		if err != nil {
			t.Fatalf("%s drift check: %v", tc.name, err)
		}
		if !drift.Known || !drift.Changed {
			t.Fatalf("%s should be known and changed: %+v", tc.name, drift)
		}
		if drift.CommandChanged != tc.wantCommand || drift.RefsChanged != tc.wantRefs || drift.DeliveryChanged != tc.wantDelivery || drift.OutputsChanged != tc.wantOutputs {
			t.Fatalf("%s drift mismatch: %+v", tc.name, drift)
		}
	}
}

func TestManifestTargetExpansionHelpersCoverManifestSurface(t *testing.T) {
	projectRoot := t.TempDir()
	writeRepoManifestForTest(t, projectRoot, `{
  "version": "v1",
  "project": {"name": "fixture"},
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "file_01", "item": "GOOGLE_SERVICE_ACCOUNT"},
    {"alias": "config_01", "item": "API_BASE_URL"}
  ],
  "requirements": [
    {"ref": "secret_01", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@GOOGLE_SERVICE_ACCOUNT", "kind": "file", "classification": "secret", "required": true},
    {"ref": "config_01", "kind": "kv", "classification": "public_config", "required": true}
  ],
  "targets": [
    {
      "name": "server.dev",
      "root": "apps/server",
      "command": ["npm", "run", "dev"],
      "delivery": [
        {"as": "env", "name": "OPENAI_API_KEY", "ref": "secret_01"},
        {"as": "file", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "@GOOGLE_SERVICE_ACCOUNT"},
        {"as": "xcconfig", "name": "API_BASE_URL", "ref": "config_01", "output": "apps/server/Config/Secrets.generated.xcconfig"}
      ],
      "examples": [
        {"format": "env", "path": "apps/server/.env.example"},
        {"format": "xcconfig", "path": "apps/server/Config/Secrets.example.xcconfig"}
      ]
    },
    {
      "name": "root.task",
      "root": ".",
      "delivery": [{"as": "env", "name": "API_BASE_URL", "ref": "config_01"}]
    }
  ]
}`)

	manifest, identity, err := LoadRepoManifestWithIdentity(projectRoot)
	if err != nil {
		t.Fatalf("load manifest with identity: %v", err)
	}
	if identity == "" {
		t.Fatal("expected manifest identity hash")
	}
	if target, ok := manifest.Target(" server.dev "); !ok || target.Name != "server.dev" {
		t.Fatalf("target lookup failed: %+v %v", target, ok)
	}
	if _, ok := manifest.Target("missing"); ok {
		t.Fatal("missing target lookup succeeded")
	}
	if req, ok := manifest.Requirement(" config_01 "); !ok || req.Kind != ItemKindKV {
		t.Fatalf("requirement lookup failed: %+v %v", req, ok)
	}
	if _, ok := manifest.Requirement("missing"); ok {
		t.Fatal("missing requirement lookup succeeded")
	}
	if item, ok := manifest.ItemNameForRef("secret_01"); !ok || item != "OPENAI_API_KEY" {
		t.Fatalf("alias item lookup = %q %v", item, ok)
	}
	if item, ok := manifest.ItemNameForRef("@GOOGLE_SERVICE_ACCOUNT"); !ok || item != "GOOGLE_SERVICE_ACCOUNT" {
		t.Fatalf("named item lookup = %q %v", item, ok)
	}
	if _, ok := manifest.ItemNameForRef("missing"); ok {
		t.Fatal("missing item lookup succeeded")
	}

	expansion, err := ExpandManifestTarget(projectRoot, "server.dev")
	if err != nil {
		t.Fatalf("expand target: %v", err)
	}
	if got := expansion.ExecutionRoot(projectRoot); got != filepath.Join(projectRoot, "apps", "server") {
		t.Fatalf("execution root = %q", got)
	}
	if expansion.Env["OPENAI_API_KEY"] != "secret_01" || expansion.Files["GOOGLE_APPLICATION_CREDENTIALS"] != "@GOOGLE_SERVICE_ACCOUNT" || expansion.XCConfig["API_BASE_URL"] != "config_01" {
		t.Fatalf("unexpected expansion: %+v", expansion)
	}
	if expansion.Outputs["API_BASE_URL"] != "apps/server/Config/Secrets.generated.xcconfig" {
		t.Fatalf("unexpected outputs: %+v", expansion.Outputs)
	}
	if expansion.Signature().Delivery == "" {
		t.Fatal("expected target delivery signature")
	}
	if !slices.Equal(expansion.Refs, []string{"@GOOGLE_SERVICE_ACCOUNT", "config_01", "secret_01"}) {
		t.Fatalf("refs not sorted/compacted: %+v", expansion.Refs)
	}
	rootExpansion, err := ExpandManifestTarget(projectRoot, "root.task")
	if err != nil {
		t.Fatalf("expand root target: %v", err)
	}
	if got := rootExpansion.ExecutionRoot(projectRoot); got != projectRoot {
		t.Fatalf("root execution root = %q", got)
	}
	if _, err := ExpandManifestTarget(projectRoot, "missing"); err == nil {
		t.Fatal("expected unknown target error")
	}
	if _, err := ExpandManifestTarget(t.TempDir(), "server.dev"); err == nil {
		t.Fatal("expected missing manifest error")
	}
}

func TestManifestCredentialSetsExpandTargetRoles(t *testing.T) {
	projectRoot := t.TempDir()
	writeRepoManifestForTest(t, projectRoot, `{
  "version": "v1",
  "references": [
    {"alias": "config_01", "item": "GOOGLE_CLIENT_ID"},
    {"alias": "secret_01", "item": "GOOGLE_CLIENT_SECRET"},
    {"alias": "config_02", "item": "GOOGLE_REDIRECT_URI"}
  ],
  "requirements": [
    {"ref": "config_01", "kind": "kv", "classification": "public_config", "required": true},
    {"ref": "secret_01", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "config_02", "kind": "kv", "classification": "public_config", "required": false}
  ],
  "credential_sets": [
    {
      "name": "google.oauth.web",
      "kind": "google_oauth_client",
      "members": {
        "client_id": "config_01",
        "client_secret": "secret_01",
        "redirect_uri": "config_02"
      }
    }
  ],
  "targets": [
    {
      "name": "server.dev",
      "delivery": [
        {"as": "env", "name": "GOOGLE_CLIENT_ID", "from_set": "google.oauth.web", "role": "client_id"},
        {"as": "env", "name": "GOOGLE_CLIENT_SECRET", "from_set": "google.oauth.web", "role": "client_secret"},
        {"as": "env", "name": "GOOGLE_REDIRECT_URI", "from_set": "GOOGLE.OAUTH.WEB", "role": "redirect_uri"}
      ]
    }
  ]
}`)

	manifest, err := LoadRepoManifest(projectRoot)
	if err != nil {
		t.Fatalf("load credential-set manifest: %v", err)
	}
	set, ok := manifest.CredentialSet("google.oauth.web")
	if !ok || set.Kind != ManifestCredentialSetGoogleOAuth || set.Members["client_secret"] != "secret_01" {
		t.Fatalf("credential set lookup failed: %+v ok=%v", set, ok)
	}
	target, ok := manifest.Target("server.dev")
	if !ok {
		t.Fatal("missing server.dev target")
	}
	if ref, ok := manifest.DeliveryRef(target.Delivery[0]); !ok || ref != "config_01" {
		t.Fatalf("delivery role ref = %q ok=%v", ref, ok)
	}
	if _, ok := manifest.CredentialSet("missing"); ok {
		t.Fatal("missing credential set lookup succeeded")
	}
	if _, ok := manifest.DeliveryRef(ManifestDelivery{FromSet: "missing", Role: "client_id"}); ok {
		t.Fatal("missing credential set delivery ref succeeded")
	}
	expansion, err := ExpandManifestTarget(projectRoot, "server.dev")
	if err != nil {
		t.Fatalf("expand credential-set target: %v", err)
	}
	if expansion.Env["GOOGLE_CLIENT_ID"] != "config_01" || expansion.Env["GOOGLE_CLIENT_SECRET"] != "secret_01" || expansion.Env["GOOGLE_REDIRECT_URI"] != "config_02" {
		t.Fatalf("unexpected credential-set expansion: %+v", expansion)
	}
	if !slices.Equal(expansion.Refs, []string{"config_01", "config_02", "secret_01"}) {
		t.Fatalf("unexpected expanded refs: %+v", expansion.Refs)
	}
	if !slices.Equal(expansion.CredentialSets, []string{"google.oauth.web"}) {
		t.Fatalf("unexpected expanded sets: %+v", expansion.CredentialSets)
	}
}

func TestManifestValidationBranchCoverage(t *testing.T) {
	projectRoot := t.TempDir()
	cases := []string{
		`{"project":{"name":"fixture"}}`,
		`{"credential_sets":[{"name":"google.oauth.web","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}]}`,
		`{"version":"v1","requirements":[{"ref":"","kind":"kv","classification":"secret"}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"},{"ref":"secret_01","kind":"kv","classification":"secret"}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"missing","kind":"kv","classification":"secret"}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"@MISSING","kind":"kv","classification":"secret"}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"file","classification":"secret"}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"OPENAI_API_KEY","ref":"secret_01"}]}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"OPENAI_API_KEY","ref":"secret_01"},{"as":"file","name":"openai_api_key","ref":"secret_01"}]}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","command":[""]}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"OPENAI_API_KEY","ref":"secret_01","output":"out.env"}]}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","examples":[{"format":"toml","path":"example.toml"}]}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"OPENAI_API_KEY"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","examples":[{"format":"env","path":"/tmp/.env.example"}]}]}`,
		`{"version":"v1","credential_sets":[{"name":"bad/name","kind":"generic","members":{"token":"secret_01"}}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"TOKEN"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"generic","members":{"token":"secret_01"}},{"name":"oauth","kind":"generic","members":{"other":"secret_01"}}]}`,
		`{"version":"v1","credential_sets":[{"name":"oauth","kind":"unknown","members":{"token":"secret_01"}}]}`,
		`{"version":"v1","credential_sets":[{"name":"oauth","kind":"generic","members":{}}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"TOKEN"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"generic","members":{"BadRole":"secret_01"}}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"TOKEN"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"generic","members":{"token":"missing"}}]}`,
		`{"version":"v1","references":[{"alias":"secret_01","item":"TOKEN"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"secret_01","client_secret":"secret_01"}}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"public_config"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"file","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01"}}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01","tenant":"config_01"}}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"GOOGLE_CLIENT_ID"}]}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"GOOGLE_CLIENT_ID","from_set":"oauth"}]}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"GOOGLE_CLIENT_ID","ref":"config_01","from_set":"oauth","role":"client_id"}]}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"GOOGLE_CLIENT_ID","from_set":"missing","role":"client_id"}]}]}`,
		`{"version":"v1","references":[{"alias":"config_01","item":"CID"},{"alias":"secret_01","item":"SEC"}],"requirements":[{"ref":"config_01","kind":"kv","classification":"public_config"},{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"oauth","kind":"google_oauth_client","members":{"client_id":"config_01","client_secret":"secret_01"}}],"targets":[{"name":"server.dev","delivery":[{"as":"env","name":"GOOGLE_CLIENT_ID","from_set":"oauth","role":"tenant"}]}]}`,
	}
	for _, body := range cases {
		if _, err := DecodeRepoManifest(projectRoot, []byte(body)); err == nil {
			t.Fatalf("expected manifest rejection for %s", body)
		}
	}
	if _, err := DecodeRepoManifest("", []byte(`{"references":[]}`)); err != nil {
		t.Fatalf("legacy empty-version manifest should remain valid: %v", err)
	}
	if _, err := DecodeRepoManifest("", []byte(`{"version":"v1","references":[],"targets":[{"name":"root.task","root":""}]}`)); err != nil {
		t.Fatalf("empty optional target root should remain valid without filesystem root: %v", err)
	}
	if _, err := DecodeRepoManifest("", []byte(`{"version":"v1","references":[{"alias":"secret_01","item":"TOKEN"}],"requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],"credential_sets":[{"name":"token.bundle","kind":"generic","members":{"token":"secret_01"}}]}`)); err != nil {
		t.Fatalf("generic credential set should remain valid: %v", err)
	}
	if err := validateManifestCredentialSetMember("broken", "token", "missing", map[string]ManifestRequirement{}, ItemKindKV, ManifestClassificationSecret); err == nil {
		t.Fatal("expected missing credential set member rejection")
	}
	if _, err := DecodeRepoManifest(projectRoot, []byte(`{"version":"v1","references":[],"value":"secret"}`)); err == nil {
		t.Fatal("expected local authority field rejection")
	}
	if _, err := DecodeRepoManifest(projectRoot, []byte(`{"version":"v1","references":[]`)); err == nil {
		t.Fatal("expected malformed JSON rejection")
	}
}

func TestManifestLowLevelHelperCoverage(t *testing.T) {
	projectRoot := t.TempDir()
	manifest := RepoManifest{References: []ManifestReference{{Alias: "secret_01", Item: "OPENAI_API_KEY"}}}
	if manifest.manifestReferenceDeclared(" ") {
		t.Fatal("empty manifest reference should not be declared")
	}
	filePath := filepath.Join(projectRoot, "existing")
	if err := os.WriteFile(filePath, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if resolved, err := resolveManifestPathSymlinks(filePath); err != nil || resolved == "" {
		t.Fatalf("resolve existing file: %q %v", resolved, err)
	}
	outside := t.TempDir()
	link := filepath.Join(projectRoot, "link")
	if err := os.Symlink(outside, link); err == nil {
		resolvedOutside, err := filepath.EvalSymlinks(outside)
		if err != nil {
			t.Fatalf("resolve outside dir: %v", err)
		}
		if resolved, err := resolveManifestPathSymlinks(filepath.Join(link, "missing", "file")); err != nil || !strings.HasPrefix(resolved, resolvedOutside) {
			t.Fatalf("resolve symlink parent: %q %v", resolved, err)
		}
	}
	if err := validateManifestRelativePath("", "nested/file", "test path", true); err != nil {
		t.Fatalf("validate rootless path: %v", err)
	}
	for _, value := range []string{"", "."} {
		if err := validateManifestRelativePath("", value, "test path", true); err == nil {
			t.Fatalf("expected required path rejection for %q", value)
		}
	}
	notDir := filepath.Join(projectRoot, "not-dir")
	if err := os.WriteFile(notDir, []byte("file"), 0o600); err != nil {
		t.Fatalf("write not-dir file: %v", err)
	}
	if err := validateManifestRelativePath(projectRoot, "not-dir/child", "test path", true); err == nil {
		t.Fatal("expected path resolution error through file parent")
	}
	origAbs := filepathAbsFn
	t.Cleanup(func() { filepathAbsFn = origAbs })
	filepathAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
	if err := validateManifestRelativePath("relative-root", "file", "test path", true); err == nil {
		t.Fatal("expected cwd-dependent abs failure")
	}
	if _, err := resolveManifestPathSymlinks("relative-file"); err == nil {
		t.Fatal("expected cwd-dependent resolve failure")
	}
	filepathAbsFn = origAbs
	for _, destination := range []string{"DYLD_INSERT_LIBRARIES", "GIT_ASKPASS", "HASP_HOME", "SAFE_NAME"} {
		_ = manifestDangerousDestination(destination)
	}
	if containsControl("safe") || !containsControl("bad\n") {
		t.Fatal("control detection mismatch")
	}
	if got := hashManifestValue(func() {}); got != "" {
		t.Fatalf("unmarshalable hash = %q", got)
	}
	if err := rejectManifestLocalAuthorityFields([]byte(`[{"nested":[{"tokens":"local"}]}]`)); err == nil {
		t.Fatal("expected nested authority field rejection")
	}
}

func TestManifestReviewEmptyAndErrorBranches(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if drift, err := handle.ManifestTargetDrift(t.TempDir(), ManifestTargetExpansion{}); err != nil || drift != (ManifestDrift{}) {
		t.Fatalf("empty drift = %+v %v", drift, err)
	}
	if err := handle.RecordManifestTargetReview(t.TempDir(), ManifestTargetExpansion{}); err != nil {
		t.Fatalf("empty record review: %v", err)
	}
	handle.state.ManifestReviews = nil
	if err := handle.RecordManifestTargetReview(t.TempDir(), ManifestTargetExpansion{TargetName: "server.dev"}); err != nil {
		t.Fatalf("record review with nil map: %v", err)
	}

	origAbs := filepathAbsFn
	t.Cleanup(func() { filepathAbsFn = origAbs })
	filepathAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
	if _, err := handle.ManifestTargetDrift("bad", ManifestTargetExpansion{TargetName: "server.dev"}); err == nil {
		t.Fatal("expected drift canonicalization error")
	}
	if err := handle.RecordManifestTargetReview("bad", ManifestTargetExpansion{TargetName: "server.dev"}); err == nil {
		t.Fatal("expected record canonicalization error")
	}
}

func manifestExpansionCopy(input ManifestTargetExpansion, mutate func(*ManifestTargetExpansion)) ManifestTargetExpansion {
	output := input
	output.Command = slices.Clone(input.Command)
	output.Env = maps.Clone(input.Env)
	output.Files = maps.Clone(input.Files)
	output.XCConfig = maps.Clone(input.XCConfig)
	output.Outputs = maps.Clone(input.Outputs)
	output.Refs = slices.Clone(input.Refs)
	output.Destinations = slices.Clone(input.Destinations)
	mutate(&output)
	return output
}

func writeRepoManifestForTest(t *testing.T, projectRoot string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(projectRoot, manifestFilename), []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func assertLoadRepoManifestRejected(t *testing.T, body string) {
	t.Helper()
	projectRoot := t.TempDir()
	writeRepoManifestForTest(t, projectRoot, body)
	assertLoadRepoManifestRejectedAtRoot(t, projectRoot)
}

func assertLoadRepoManifestRejectedAtRoot(t *testing.T, projectRoot string) {
	t.Helper()
	if _, err := LoadRepoManifest(projectRoot); err == nil {
		t.Fatal("expected manifest to be rejected")
	}
}
