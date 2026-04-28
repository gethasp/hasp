package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type nthWriteErrWriter struct {
	allow int
	count int
}

func (w *nthWriteErrWriter) Write(p []byte) (int, error) {
	if w.count >= w.allow {
		return 0, errors.New("write fail")
	}
	w.count++
	return len(p), nil
}

type matchErrWriter struct {
	match string
}

func (w matchErrWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.match) {
		return 0, errors.New("write fail")
	}
	return len(p), nil
}

func TestCLIOutputRenderers(t *testing.T) {
	lockAppSeams(t)

	now := time.Now().UTC()
	secretMeta := secretMetadataView{
		Name:           "API_TOKEN",
		NamedReference: "@API_TOKEN",
		Kind:           store.ItemKindKV,
		CreatedAt:      now.Format(timeRFC3339),
		UpdatedAt:      now.Format(timeRFC3339),
		Exposures: []store.ItemExposure{{
			ProjectRoot: "/tmp/project",
			Reference:   "secret_01",
		}},
	}
	bootstrapProfile := profiles.Profile{ID: "claude-code", Name: "Claude Code", Transport: "mcp-stdio", Command: []string{"hasp", "agent", "mcp", "claude-code"}}

	cases := []struct {
		name    string
		run     func(*bytes.Buffer) error
		mustSee string
	}{
		{
			name: "renderSimpleAction",
			run: func(out *bytes.Buffer) error {
				return renderSimpleAction(context.Background(), out, "Title", "Lead", cliPair("A", "B"))
			},
			mustSee: "Lead",
		},
		{
			name: "renderImportCommandResultPreviewAndApplied",
			run: func(out *bytes.Buffer) error {
				if err := renderImportCommandResult(out, importPreview{
					Source:           "stdin",
					Format:           "env",
					CaptureModeLabel: "local-import-stdin",
					BindToProject:    true,
					PlannedChanges:   []importPlanItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}},
					Notes:            []string{"note"},
				}, nil, false); err != nil {
					return err
				}
				return renderImportCommandResult(out, importPreview{}, &store.ImportResult{Imported: []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}}}, true)
			},
			mustSee: "Imported 1 item",
		},
		{
			name: "renderSecretMutationsAndMetadata",
			run: func(out *bytes.Buffer) error {
				if err := renderSecretMutations(out, "Secret add", "done", []secretMutationView{{Name: "API_TOKEN", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV, Outcome: "created", Reference: "secret_01", ProjectRoot: "/tmp/project"}}, []string{"MISSING"}); err != nil {
					return err
				}
				if err := renderSecretMetadata(out, secretMeta, false); err != nil {
					return err
				}
				return renderSecretMetadata(out, secretMeta, true)
			},
			mustSee: "Copied the secret value to the clipboard",
		},
		{
			name: "renderSecretList",
			run: func(out *bytes.Buffer) error {
				if err := renderSecretList(out, nil); err != nil {
					return err
				}
				return renderSecretList(out, []secretMetadataView{secretMeta})
			},
			mustSee: "@API_TOKEN",
		},
		{
			name: "renderProjectBindingStatusAndAdopt",
			run: func(out *bytes.Buffer) error {
				binding := store.Binding{ID: "binding", CanonicalRoot: "/tmp/project", Aliases: map[string]string{"secret_01": "API_TOKEN"}, DefaultCapturePolicy: store.PolicySession, HookInstalled: true}
				visible := []store.VisibleReference{{Alias: "secret_01", ItemName: "API_TOKEN", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV, PolicyLevel: store.PolicySession, LeaseStatus: "active"}}
				if err := renderProjectBinding(out, "Project bound", "Bound the repository to HASP.", binding); err != nil {
					return err
				}
				if err := renderProjectStatus(out, binding, visible); err != nil {
					return err
				}
				return renderProjectAdoptResult(out, projectAdoptResult{
					Under:        "/tmp",
					Preview:      true,
					Defaults:     projectDefaults{DefaultPolicy: store.PolicySession, AutoInstallHooks: true},
					Candidates:   []projectAdoptCandidate{{ProjectRoot: "/tmp/project", Adopted: true, HooksEnabled: true, Reason: "adopted"}},
					ScannedRoots: 1,
					AdoptedCount: 1,
				})
			},
			mustSee: "Project adoption",
		},
		{
			name: "renderConsumersAndChecks",
			run: func(out *bytes.Buffer) error {
				appConsumer := store.AppConsumer{Name: "myapp", ProjectRoot: "/tmp/project", Command: []string{"sh", "-lc", "run"}, Bindings: []store.AppBinding{{SecretName: "API_TOKEN", Delivery: store.AppDeliveryEnv, Target: "OPENAI_API_KEY"}}, LauncherPath: "/tmp/bin/myapp"}
				agentConsumer := store.AgentConsumer{Name: "claude-code", AgentID: "claude-code", ProjectRoot: "/tmp/project", ConfigPath: "/tmp/.claude.json"}
				if err := renderAppConsumerSummary(out, "App connected", "saved", appConsumer, appPathUpdateResult{ConfigPath: "/tmp/.zshrc", Changed: true}); err != nil {
					return err
				}
				if err := renderAppConsumerList(out, []store.AppConsumer{appConsumer}); err != nil {
					return err
				}
				if err := renderAgentConsumerSummary(out, "Agent connected", "saved", agentConsumer, setupAgentOutcome{Changed: true, BackupPath: "/tmp/backup"}); err != nil {
					return err
				}
				if err := renderAgentConsumerList(out, []store.AgentConsumer{agentConsumer}); err != nil {
					return err
				}
				return renderRepoCheckResult(out, "/tmp/project", []map[string]string{{"path": "/tmp/project/.env", "item_name": "API_TOKEN"}}, true)
			},
			mustSee: "Repo check",
		},
		{
			name: "renderRuntimeAndBootstrap",
			run: func(out *bytes.Buffer) error {
				if err := renderBackupResult(out, "Backup", "saved", "/tmp/backup.json", store.AuditCheckpoint{Sequence: 1, Hash: "abc"}); err != nil {
					return err
				}
				if err := renderPingResult(out, runtime.PingResponse{Name: "hasp", Version: "test", ServerTime: now}); err != nil {
					return err
				}
				if err := renderSessionOpenResult(out, "session-1", "agent", "/tmp/project", now.Format(timeRFC3339)); err != nil {
					return err
				}
				if err := renderSessionResolveResult(out, runtime.ResolveSessionResponse{Session: runtime.SessionView{ID: "session-1", LocalUser: "user", HostLabel: "agent", ProjectRoot: "/tmp/project", LastSeenAt: now, ExpiresAt: now}}); err != nil {
					return err
				}
				if err := renderBootstrapSummary(out, bootstrapResult{
					SupportTier:  "first-class-profile",
					Profile:      bootstrapProfile,
					ProjectRoot:  "/tmp/project",
					InitState:    "created",
					HooksEnabled: true,
					Binding:      store.Binding{ID: "binding"},
					BoundAliases: map[string]string{"secret_01": "API_TOKEN"},
					Imported:     []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}},
					NextSteps:    []string{"next"},
				}); err != nil {
					return err
				}
				if err := renderBootstrapDoctorSummary(out, bootstrapDoctorResult{
					Profile:              bootstrapProfile,
					ProjectCanonicalRoot: "/tmp/project",
					VaultStatus:          "existing",
					HooksRequested:       true,
					HooksPresent:         true,
					Checks: map[string]profiles.SupportCheck{
						"vault": {Status: "pass", Detail: "ok"},
					},
					PlannedImportSummary: []map[string]any{{"source": "stdin", "format": "env"}},
				}); err != nil {
					return err
				}
				if err := renderWriteEnvResult(out, "/tmp/.env", 2, "warning"); err != nil {
					return err
				}
				return renderBootstrapProfilesSummary(out, map[string]any{
					"profiles": []any{
						map[string]any{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"},
					},
				})
			},
			mustSee: "Bootstrap profiles",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tc.run(&out); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !strings.Contains(out.String(), tc.mustSee) {
				t.Fatalf("%s output missing %q in %q", tc.name, tc.mustSee, out.String())
			}
		})
	}

	t.Run("json wrappers and helper branches", func(t *testing.T) {
		var out bytes.Buffer
		if err := renderBootstrapProfileListingMaybeHuman(context.Background(), &out, true, map[string]any{"profiles": []map[string]any{{"id": "claude-code"}}}); err != nil {
			t.Fatalf("renderBootstrapProfileListingMaybeHuman: %v", err)
		}
		if !json.Valid(out.Bytes()) {
			t.Fatalf("expected json output, got %q", out.String())
		}
		out.Reset()
		if err := renderPingJSONOrHuman(context.Background(), &out, true, runtime.PingResponse{Name: "hasp"}); err != nil {
			t.Fatalf("renderPingJSONOrHuman: %v", err)
		}
		out.Reset()
		if err := renderPingJSONOrHuman(context.Background(), &out, false, runtime.PingResponse{Name: "hasp"}); err != nil {
			t.Fatalf("renderPingJSONOrHuman human: %v", err)
		}
		out.Reset()
		if err := renderBootstrapJSONOrHuman(context.Background(), &out, true, bootstrapResult{}); err != nil {
			t.Fatalf("renderBootstrapJSONOrHuman: %v", err)
		}
		out.Reset()
		if err := renderBootstrapJSONOrHuman(context.Background(), &out, false, bootstrapResult{Profile: bootstrapProfile, ProjectRoot: "/tmp/project"}); err != nil {
			t.Fatalf("renderBootstrapJSONOrHuman human: %v", err)
		}
		out.Reset()
		if err := renderBootstrapDoctorJSONOrHuman(context.Background(), &out, true, bootstrapDoctorResult{}); err != nil {
			t.Fatalf("renderBootstrapDoctorJSONOrHuman: %v", err)
		}
		out.Reset()
		if err := renderBootstrapDoctorJSONOrHuman(context.Background(), &out, false, bootstrapDoctorResult{}); err != nil {
			t.Fatalf("renderBootstrapDoctorJSONOrHuman human: %v", err)
		}
		out.Reset()
		if err := renderSecretListJSONOrHuman(context.Background(), &out, true, []secretMetadataView{secretMeta}); err != nil {
			t.Fatalf("renderSecretListJSONOrHuman: %v", err)
		}
		out.Reset()
		if err := renderSecretListJSONOrHuman(context.Background(), &out, false, []secretMetadataView{secretMeta}); err != nil {
			t.Fatalf("renderSecretListJSONOrHuman human: %v", err)
		}
		payload := secretGetJSONPayload(secretMeta, true, true, []byte{0xff, 0x00})
		// hasp-jx3r: value_base64 is now nested inside "secret", not at the top level.
		secretObj, _ := payload["secret"].(map[string]any)
		if payload["copied"] != true || secretObj["value_base64"] != base64.StdEncoding.EncodeToString([]byte{0xff, 0x00}) {
			t.Fatalf("unexpected secretGetJSONPayload %+v", payload)
		}
		if cliLead(errWriter{err: nil}, "1;32", "!", "[ok]", "text") == "" {
			t.Fatal("expected cliLead output")
		}
		if cliOutcome(&bytes.Buffer{}, "created") == "" || cliOutcome(&bytes.Buffer{}, "skipped") == "" || cliOutcome(&bytes.Buffer{}, "existing") == "" || cliOutcome(&bytes.Buffer{}, "other") == "" {
			t.Fatal("expected cliOutcome values")
		}
		if first := cliPlural(1, "item", "items"); first != "item" {
			t.Fatalf("cliPlural singular = %q", first)
		}
		if devNull, err := os.Open("/dev/null"); err == nil {
			defer devNull.Close()
			if value := cliLead(devNull, "1;32", "!", "[ok]", "text"); value == "" {
				t.Fatal("expected cliLead output with file writer")
			}
		}
		if line := cliBullet(&out, "Label", "", "detail"); !strings.Contains(line, "detail") {
			t.Fatalf("cliBullet filtered details = %q", line)
		}
		if err := cliWriteStage(&out, "Title", ""); err != nil {
			t.Fatalf("cliWriteStage empty lead: %v", err)
		}
		if payload := secretGetJSONPayload(secretMeta, false, false, nil); payload["copied"] != nil || payload["value"] != nil || payload["value_base64"] != nil {
			t.Fatalf("unexpected secretGetJSONPayload without flags %+v", payload)
		}
		// hasp-jx3r: value is now nested inside "secret", not at the top level.
		if payload := secretGetJSONPayload(secretMeta, false, true, []byte("abc123")); func() bool {
			sm, ok := payload["secret"].(map[string]any)
			return !ok || sm["value"] != "abc123"
		}() {
			t.Fatalf("expected utf8 reveal payload with secret.value=abc123, got %+v", payload)
		}
		if err := renderImportCommandResult(&out, importPreview{Source: "stdin", Format: "env"}, nil, false); err != nil {
			t.Fatalf("renderImportCommandResult minimal preview: %v", err)
		}
		if err := renderImportCommandResult(&out, importPreview{Source: "stdin", Format: "env"}, nil, true); err != nil {
			t.Fatalf("renderImportCommandResult applied nil result: %v", err)
		}
		if err := renderImportCommandResult(&out, importPreview{}, &store.ImportResult{Imported: []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV}}}, true); err != nil {
			t.Fatalf("renderImportCommandResult applied imported no alias: %v", err)
		}
		if err := renderAppConsumerSummary(&out, "App", "lead", store.AppConsumer{Name: "myapp"}, appPathUpdateResult{}); err != nil {
			t.Fatalf("renderAppConsumerSummary no bindings: %v", err)
		}
		if err := renderBootstrapSummary(&out, bootstrapResult{Profile: bootstrapProfile}); err != nil {
			t.Fatalf("renderBootstrapSummary minimal 2: %v", err)
		}
		if err := renderBootstrapDoctorSummary(&out, bootstrapDoctorResult{Checks: map[string]profiles.SupportCheck{}}); err != nil {
			t.Fatalf("renderBootstrapDoctorSummary minimal 2: %v", err)
		}
	})

	t.Run("empty-state branches", func(t *testing.T) {
		var out bytes.Buffer
		binding := store.Binding{CanonicalRoot: "/tmp/project"}
		if err := renderProjectStatus(&out, binding, nil); err != nil {
			t.Fatalf("renderProjectStatus empty: %v", err)
		}
		if err := renderProjectAdoptResult(&out, projectAdoptResult{
			Under:        "/tmp",
			Preview:      false,
			Defaults:     projectDefaults{},
			ScannedRoots: 0,
			AdoptedCount: 0,
		}); err != nil {
			t.Fatalf("renderProjectAdoptResult empty: %v", err)
		}
		if err := renderAppConsumerList(&out, nil); err != nil {
			t.Fatalf("renderAppConsumerList empty: %v", err)
		}
		if err := renderAgentConsumerList(&out, nil); err != nil {
			t.Fatalf("renderAgentConsumerList empty: %v", err)
		}
		if err := renderRepoCheckResult(&out, "/tmp/project", nil, false); err != nil {
			t.Fatalf("renderRepoCheckResult empty: %v", err)
		}
		if err := renderBootstrapDoctorJSONOrHuman(context.Background(), &out, false, bootstrapDoctorResult{}); err != nil {
			t.Fatalf("renderBootstrapDoctorJSONOrHuman human: %v", err)
		}
		if err := renderBootstrapProfilesSummary(&out, map[string]any{"profiles": []map[string]any{}}); err != nil {
			t.Fatalf("renderBootstrapProfilesSummary empty: %v", err)
		}
		if err := renderProjectBinding(&out, "Project", "lead", store.Binding{CanonicalRoot: "/tmp/project"}); err != nil {
			t.Fatalf("renderProjectBinding empty aliases: %v", err)
		}
		if err := renderImportCommandResult(&out, importPreview{Source: "stdin", Format: "env"}, &store.ImportResult{}, true); err != nil {
			t.Fatalf("renderImportCommandResult empty imported: %v", err)
		}
		if err := renderSecretMutations(&out, "Secrets", "lead", nil, nil); err != nil {
			t.Fatalf("renderSecretMutations empty: %v", err)
		}
		if err := renderSecretMetadata(&out, secretMetadataView{Name: "API_TOKEN", Kind: store.ItemKindKV}, false); err != nil {
			t.Fatalf("renderSecretMetadata empty exposures: %v", err)
		}
		if err := renderAppConsumerSummary(&out, "App", "lead", store.AppConsumer{Name: "myapp"}, appPathUpdateResult{}); err != nil {
			t.Fatalf("renderAppConsumerSummary minimal: %v", err)
		}
		if err := renderAgentConsumerSummary(&out, "Agent", "lead", store.AgentConsumer{Name: "claude-code", AgentID: "claude-code"}, setupAgentOutcome{}); err != nil {
			t.Fatalf("renderAgentConsumerSummary minimal: %v", err)
		}
		if err := renderBootstrapSummary(&out, bootstrapResult{Profile: bootstrapProfile, ProjectRoot: "/tmp/project", Binding: store.Binding{}}); err != nil {
			t.Fatalf("renderBootstrapSummary minimal: %v", err)
		}
		if err := renderBootstrapProfileListingMaybeHuman(context.Background(), &out, false, map[string]any{"profiles": []any{map[string]any{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}}}); err != nil {
			t.Fatalf("renderBootstrapProfileListingMaybeHuman human: %v", err)
		}
	})

	t.Run("writer failures", func(t *testing.T) {
		if err := renderSimpleAction(context.Background(), errWriter{err: errors.New("write fail")}, "Title", "Lead", cliPair("A", "B")); err == nil {
			t.Fatal("expected writer failure")
		}
		if err := renderSecretExposures(errWriter{err: errors.New("write fail")}, nil); err == nil {
			t.Fatal("expected renderSecretExposures writer failure")
		}
		if err := renderBindingAliases(errWriter{err: errors.New("write fail")}, nil); err == nil {
			t.Fatal("expected renderBindingAliases writer failure")
		}
	})

	t.Run("additional branch variants", func(t *testing.T) {
		var out bytes.Buffer
		if err := cliWriteStage(errWriter{err: errors.New("write fail")}, "Title", "Lead"); err == nil {
			t.Fatal("expected cliWriteStage failure")
		}
		if err := renderSecretMutations(&out, "Secrets", "lead", []secretMutationView{{Name: "API_TOKEN", Outcome: "created", Exposures: []store.ItemExposure{{ProjectRoot: "/tmp/project", Reference: "secret_01"}}}}, nil); err != nil {
			t.Fatalf("renderSecretMutations exposures: %v", err)
		}
		if err := renderSecretMetadata(&out, secretMetadataView{Name: "API_TOKEN", Kind: store.ItemKindKV}, true); err != nil {
			t.Fatalf("renderSecretMetadata copied: %v", err)
		}
		if err := renderSecretList(&out, []secretMetadataView{{Name: "API_TOKEN", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV}}); err != nil {
			t.Fatalf("renderSecretList minimal: %v", err)
		}
		if err := renderProjectBinding(&out, "Project", "lead", store.Binding{CanonicalRoot: "/tmp/project", HookInstalled: true, DefaultCapturePolicy: store.PolicySession}); err != nil {
			t.Fatalf("renderProjectBinding minimal: %v", err)
		}
		if err := renderProjectStatus(&out, store.Binding{CanonicalRoot: "/tmp/project"}, []store.VisibleReference{{Alias: "secret_01", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV, PolicyLevel: store.PolicySession, LeaseStatus: "inactive"}}); err != nil {
			t.Fatalf("renderProjectStatus visible: %v", err)
		}
		if err := renderProjectAdoptResult(&out, projectAdoptResult{
			Under:        "/tmp",
			Defaults:     projectDefaults{},
			Candidates:   []projectAdoptCandidate{{ProjectRoot: "/tmp/project", AlreadyManaged: true, HooksEnabled: true}},
			ScannedRoots: 1,
		}); err != nil {
			t.Fatalf("renderProjectAdoptResult already managed: %v", err)
		}
		if err := renderAppConsumerSummary(&out, "App", "lead", store.AppConsumer{Name: "myapp", LauncherPath: "/tmp/bin/myapp", Bindings: []store.AppBinding{{Target: "OPENAI_API_KEY", Delivery: store.AppDeliveryEnv, SecretName: "API_TOKEN"}}}, appPathUpdateResult{}); err != nil {
			t.Fatalf("renderAppConsumerSummary bindings: %v", err)
		}
		if err := renderAppConsumerList(&out, []store.AppConsumer{{Name: "myapp"}}); err != nil {
			t.Fatalf("renderAppConsumerList minimal: %v", err)
		}
		if err := renderAgentConsumerList(&out, []store.AgentConsumer{{Name: "claude", AgentID: "claude-code"}}); err != nil {
			t.Fatalf("renderAgentConsumerList minimal: %v", err)
		}
		if err := renderRepoCheckResult(&out, "/tmp/project", []map[string]string{{"path": "/tmp/project/.env", "item_name": "API_TOKEN"}}, false); err != nil {
			t.Fatalf("renderRepoCheckResult matches: %v", err)
		}
		if err := renderBackupResult(&out, "Backup", "lead", "/tmp/backup", store.AuditCheckpoint{}); err != nil {
			t.Fatalf("renderBackupResult minimal: %v", err)
		}
		if err := renderSessionResolveResult(&out, runtime.ResolveSessionResponse{Session: runtime.SessionView{ID: "session-1", LocalUser: "user", HostLabel: "agent", ProjectRoot: "/tmp/project"}}); err != nil {
			t.Fatalf("renderSessionResolveResult minimal: %v", err)
		}
		if err := renderBootstrapProfilesSummary(&out, map[string]any{"profiles": []map[string]any{{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}}}); err != nil {
			t.Fatalf("renderBootstrapProfilesSummary typed map: %v", err)
		}
		if err := renderBootstrapProfilesSummary(&out, map[string]any{
			"profiles":     []map[string]any{{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}},
			"generic_path": genericCompatibilitySurface(),
		}); err != nil {
			t.Fatalf("renderBootstrapProfilesSummary generic path: %v", err)
		}

		countWriter := &setupCountWriter{}
		if err := renderBootstrapProfilesSummary(countWriter, map[string]any{
			"profiles":     []map[string]any{{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}},
			"generic_path": genericCompatibilitySurface(),
		}); err != nil {
			t.Fatalf("count renderBootstrapProfilesSummary generic path: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := renderBootstrapProfilesSummary(writer, map[string]any{
				"profiles":     []map[string]any{{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}},
				"generic_path": genericCompatibilitySurface(),
			}); err == nil {
				t.Fatalf("expected renderBootstrapProfilesSummary generic-path failure at call %d", failAt)
			}
		}

		origNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
		origTerm, hadTerm := os.LookupEnv("TERM")
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm-256color")
		if devNull, err := os.Open("/dev/null"); err == nil {
			defer devNull.Close()
			if value := cliLead(devNull, "1;32", "!", "[ok]", "text"); !strings.Contains(value, "\x1b[") {
				t.Fatalf("expected colorized cliLead output, got %q", value)
			}
		}
		if hadNoColor {
			t.Setenv("NO_COLOR", origNoColor)
		}
		if hadTerm {
			t.Setenv("TERM", origTerm)
		}
	})
}

func TestCLIOutputWriterFailureMatrix(t *testing.T) {
	lockAppSeams(t)

	now := time.Now().UTC()
	secretMeta := secretMetadataView{
		Name:           "API_TOKEN",
		NamedReference: "@API_TOKEN",
		Kind:           store.ItemKindKV,
		CreatedAt:      now.Format(timeRFC3339),
		UpdatedAt:      now.Format(timeRFC3339),
		Exposures:      []store.ItemExposure{{ProjectRoot: "/tmp/project", Reference: "secret_01"}},
	}
	bootstrapProfile := profiles.Profile{ID: "claude-code", Name: "Claude Code", Transport: "mcp-stdio"}
	renderers := []func(io.Writer) error{
		func(w io.Writer) error {
			return renderImportCommandResult(w, importPreview{
				Source:           "stdin",
				Format:           "env",
				CaptureModeLabel: "local-import-stdin",
				BindToProject:    true,
				PlannedChanges:   []importPlanItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}},
				Notes:            []string{"note"},
			}, &store.ImportResult{Imported: []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}}}, true)
		},
		func(w io.Writer) error {
			return renderSecretMutations(w, "Secrets", "lead", []secretMutationView{{Name: "API_TOKEN", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV, Outcome: "created", Reference: "secret_01", ProjectRoot: "/tmp/project"}}, []string{"missing"})
		},
		func(w io.Writer) error { return renderSecretMetadata(w, secretMeta, false) },
		func(w io.Writer) error { return renderSecretExposures(w, secretMeta.Exposures) },
		func(w io.Writer) error { return renderSecretList(w, []secretMetadataView{secretMeta}) },
		func(w io.Writer) error {
			return renderProjectBinding(w, "Project", "lead", store.Binding{CanonicalRoot: "/tmp/project", ID: "binding", Aliases: map[string]string{"secret_01": "API_TOKEN"}, DefaultCapturePolicy: store.PolicySession, HookInstalled: true})
		},
		func(w io.Writer) error { return renderBindingAliases(w, map[string]string{"secret_01": "API_TOKEN"}) },
		func(w io.Writer) error {
			return renderProjectStatus(w, store.Binding{CanonicalRoot: "/tmp/project"}, []store.VisibleReference{{Alias: "secret_01", NamedReference: "@API_TOKEN", Kind: store.ItemKindKV, PolicyLevel: store.PolicySession, LeaseStatus: "active"}})
		},
		func(w io.Writer) error {
			return renderProjectAdoptResult(w, projectAdoptResult{Under: "/tmp", Defaults: projectDefaults{}, Candidates: []projectAdoptCandidate{{ProjectRoot: "/tmp/project", Adopted: true, HooksEnabled: true}}, ScannedRoots: 1, AdoptedCount: 1})
		},
		func(w io.Writer) error {
			return renderAppConsumerSummary(w, "App", "lead", store.AppConsumer{Name: "myapp", ProjectRoot: "/tmp/project", Command: []string{"sh", "-lc", "run"}, Bindings: []store.AppBinding{{Target: "OPENAI_API_KEY", Delivery: store.AppDeliveryEnv, SecretName: "API_TOKEN"}}, LauncherPath: "/tmp/bin/myapp"}, appPathUpdateResult{Changed: true, ConfigPath: "/tmp/.zshrc"})
		},
		func(w io.Writer) error {
			return renderAppConsumerList(w, []store.AppConsumer{{Name: "myapp", ProjectRoot: "/tmp/project", LauncherPath: "/tmp/bin/myapp"}})
		},
		func(w io.Writer) error {
			return renderAgentConsumerSummary(w, "Agent", "lead", store.AgentConsumer{Name: "claude-code", AgentID: "claude-code", ProjectRoot: "/tmp/project", ConfigPath: "/tmp/.claude.json"}, setupAgentOutcome{Changed: true, BackupPath: "/tmp/.claude.json.bak"})
		},
		func(w io.Writer) error {
			return renderAgentConsumerList(w, []store.AgentConsumer{{Name: "claude-code", AgentID: "claude-code", ProjectRoot: "/tmp/project", ConfigPath: "/tmp/.claude.json"}})
		},
		func(w io.Writer) error { return renderWriteEnvResult(w, "/tmp/.env", 2, "warning") },
		func(w io.Writer) error {
			return renderRepoCheckResult(w, "/tmp/project", []map[string]string{{"path": "/tmp/project/.env", "item_name": "API_TOKEN"}}, true)
		},
		func(w io.Writer) error {
			return renderBackupResult(w, "Backup", "lead", "/tmp/backup.json", store.AuditCheckpoint{Sequence: 1, Hash: "hash"})
		},
		func(w io.Writer) error {
			return renderPingResult(w, runtime.PingResponse{Name: "hasp", Version: "test", ServerTime: now})
		},
		func(w io.Writer) error {
			return renderSessionOpenResult(w, "session-1", "agent", "/tmp/project", now.Format(timeRFC3339))
		},
		func(w io.Writer) error {
			return renderSessionResolveResult(w, runtime.ResolveSessionResponse{Session: runtime.SessionView{ID: "session-1", LocalUser: "user", HostLabel: "agent", ProjectRoot: "/tmp/project", LastSeenAt: now, ExpiresAt: now}})
		},
		func(w io.Writer) error {
			return renderBootstrapSummary(w, bootstrapResult{Profile: bootstrapProfile, ProjectRoot: "/tmp/project", Binding: store.Binding{ID: "binding"}, BoundAliases: map[string]string{"secret_01": "API_TOKEN"}, Imported: []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV, Alias: "secret_01"}}, NextSteps: []string{"next"}})
		},
		func(w io.Writer) error {
			return renderBootstrapDoctorSummary(w, bootstrapDoctorResult{Profile: bootstrapProfile, ProjectCanonicalRoot: "/tmp/project", VaultStatus: "existing", Checks: map[string]profiles.SupportCheck{"vault": {Status: "pass", Detail: "ok"}}, PlannedImportSummary: []map[string]any{{"source": "stdin", "format": "env"}}})
		},
		func(w io.Writer) error {
			return renderBootstrapProfilesSummary(w, map[string]any{"profiles": []any{map[string]any{"id": "claude-code", "support_tier": "first-class-profile", "transport": "mcp-stdio"}}})
		},
	}

	for idx, render := range renderers {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			for allow := 0; allow < 50; allow++ {
				writer := &nthWriteErrWriter{allow: allow}
				_ = render(writer)
			}
		})
	}
}

func TestRenderImportCommandResultPreviewWriteFailure(t *testing.T) {
	lockAppSeams(t)

	err := renderImportCommandResult(matchErrWriter{match: "API_TOKEN"}, importPreview{
		Source:         "stdin",
		Format:         "env",
		PlannedChanges: []importPlanItem{{Name: "API_TOKEN", Kind: store.ItemKindKV}},
	}, nil, false)
	if err == nil || err.Error() != "write fail" {
		t.Fatalf("expected preview write failure, got %v", err)
	}
}
