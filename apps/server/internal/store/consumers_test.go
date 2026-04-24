package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAppConsumerCRUD(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	if _, err := handle.UpsertAppConsumer(AppConsumer{}); err == nil {
		t.Fatal("expected missing app consumer name failure")
	}
	if _, err := handle.UpsertAppConsumer(AppConsumer{Name: "myapp"}); err == nil {
		t.Fatal("expected missing app command failure")
	}

	appConsumer, err := handle.UpsertAppConsumer(AppConsumer{
		Name:        "myapp",
		ProjectRoot: t.TempDir(),
		Command:     []string{"sh", "-lc", "python app.py"},
		Bindings: []AppBinding{
			{SecretName: "OPENAI_API_KEY", Delivery: AppDeliveryEnv, Target: "OPENAI_API_KEY"},
		},
		DotenvEnv:    "ENV_FILE",
		LauncherPath: "/tmp/myapp",
	})
	if err != nil {
		t.Fatalf("upsert app consumer: %v", err)
	}
	if appConsumer.CreatedAt.IsZero() || appConsumer.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps on app consumer: %+v", appConsumer)
	}
	readBack, err := handle.GetAppConsumer("myapp")
	if err != nil {
		t.Fatalf("get app consumer: %v", err)
	}
	if readBack.Name != "myapp" || readBack.DotenvEnv != "ENV_FILE" || len(readBack.Bindings) != 1 {
		t.Fatalf("unexpected app consumer round trip: %+v", readBack)
	}
	consumers := handle.ListAppConsumers()
	if len(consumers) != 1 || consumers[0].Name != "myapp" {
		t.Fatalf("unexpected app consumer list: %+v", consumers)
	}

	updated, err := handle.UpsertAppConsumer(AppConsumer{
		Name:        "myapp",
		ProjectRoot: readBack.ProjectRoot,
		Command:     []string{"sh", "-lc", "python main.py"},
	})
	if err != nil {
		t.Fatalf("update app consumer: %v", err)
	}
	if updated.CreatedAt != readBack.CreatedAt || !updated.UpdatedAt.After(readBack.UpdatedAt) {
		t.Fatalf("expected stable create time and newer update time: old=%+v new=%+v", readBack, updated)
	}

	reopened, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	if persisted, err := reopened.GetAppConsumer("myapp"); err != nil || persisted.Name != "myapp" {
		t.Fatalf("expected persisted app consumer, got %+v err=%v", persisted, err)
	}

	if err := handle.DeleteAppConsumer("myapp"); err != nil {
		t.Fatalf("delete app consumer: %v", err)
	}
	if _, err := handle.GetAppConsumer("myapp"); !errors.Is(err, ErrConsumerNotFound) {
		t.Fatalf("expected missing app consumer after delete, got %v", err)
	}
	if err := handle.DeleteAppConsumer("myapp"); !errors.Is(err, ErrConsumerNotFound) {
		t.Fatalf("expected consumer not found on second delete, got %v", err)
	}

	if _, err := handle.UpsertAppConsumer(AppConsumer{Name: "zapp", Command: []string{"true"}}); err != nil {
		t.Fatalf("upsert zapp: %v", err)
	}
	if _, err := handle.UpsertAppConsumer(AppConsumer{Name: "aapp", Command: []string{"true"}}); err != nil {
		t.Fatalf("upsert aapp: %v", err)
	}
	consumers = handle.ListAppConsumers()
	if len(consumers) != 2 || consumers[0].Name != "aapp" || consumers[1].Name != "zapp" {
		t.Fatalf("expected sorted app consumers, got %+v", consumers)
	}
}

func TestAgentConsumerCRUD(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	if _, err := handle.UpsertAgentConsumer(AgentConsumer{}); err == nil {
		t.Fatal("expected missing agent name failure")
	}
	if _, err := handle.UpsertAgentConsumer(AgentConsumer{Name: "claude"}); err == nil {
		t.Fatal("expected missing agent id failure")
	}
	if _, err := handle.UpsertAgentConsumer(AgentConsumer{Name: "claude", AgentID: "claude-code"}); err == nil {
		t.Fatal("expected missing agent config path failure")
	}

	agentConsumer, err := handle.UpsertAgentConsumer(AgentConsumer{
		Name:        "claude",
		AgentID:     "claude-code",
		ProjectRoot: t.TempDir(),
		ConfigPath:  "/tmp/.claude.json",
	})
	if err != nil {
		t.Fatalf("upsert agent consumer: %v", err)
	}
	if agentConsumer.CreatedAt.IsZero() || agentConsumer.UpdatedAt.IsZero() {
		t.Fatalf("expected timestamps on agent consumer: %+v", agentConsumer)
	}
	readBack, err := handle.GetAgentConsumer("claude")
	if err != nil {
		t.Fatalf("get agent consumer: %v", err)
	}
	if readBack.AgentID != "claude-code" || readBack.ConfigPath != "/tmp/.claude.json" {
		t.Fatalf("unexpected agent consumer round trip: %+v", readBack)
	}
	agents := handle.ListAgentConsumers()
	if len(agents) != 1 || agents[0].Name != "claude" {
		t.Fatalf("unexpected agent consumer list: %+v", agents)
	}

	updated, err := handle.UpsertAgentConsumer(AgentConsumer{
		Name:       "claude",
		AgentID:    "claude-code",
		ConfigPath: "/tmp/.claude-new.json",
	})
	if err != nil {
		t.Fatalf("update agent consumer: %v", err)
	}
	if updated.CreatedAt != readBack.CreatedAt || !updated.UpdatedAt.After(readBack.UpdatedAt) {
		t.Fatalf("expected stable create time and newer update time: old=%+v new=%+v", readBack, updated)
	}

	if err := handle.DeleteAgentConsumer("claude"); err != nil {
		t.Fatalf("delete agent consumer: %v", err)
	}
	if _, err := handle.GetAgentConsumer("claude"); !errors.Is(err, ErrConsumerNotFound) {
		t.Fatalf("expected missing agent consumer after delete, got %v", err)
	}
	if err := handle.DeleteAgentConsumer("claude"); !errors.Is(err, ErrConsumerNotFound) {
		t.Fatalf("expected consumer not found on second agent delete, got %v", err)
	}

	if _, err := handle.UpsertAgentConsumer(AgentConsumer{Name: "zagent", AgentID: "cursor", ConfigPath: "/tmp/z"}); err != nil {
		t.Fatalf("upsert zagent: %v", err)
	}
	if _, err := handle.UpsertAgentConsumer(AgentConsumer{Name: "aagent", AgentID: "claude-code", ConfigPath: "/tmp/a"}); err != nil {
		t.Fatalf("upsert aagent: %v", err)
	}
	agents = handle.ListAgentConsumers()
	if len(agents) != 2 || agents[0].Name != "aagent" || agents[1].Name != "zagent" {
		t.Fatalf("expected sorted agent consumers, got %+v", agents)
	}
}

func TestAgentConsumerCreatePreservesExplicitCreatedAt(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	createdAt := time.Unix(1700000000, 0).UTC()
	consumer, err := handle.UpsertAgentConsumer(AgentConsumer{
		Name:       "  codex-cli  ",
		AgentID:    "codex-cli",
		ConfigPath: "/tmp/codex.toml",
		CreatedAt:  createdAt,
	})
	if err != nil {
		t.Fatalf("upsert agent consumer: %v", err)
	}
	if consumer.Name != "codex-cli" {
		t.Fatalf("expected trimmed agent name, got %q", consumer.Name)
	}
	if !consumer.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected explicit create time to be preserved, got %v", consumer.CreatedAt)
	}
}

func TestConsumerAuditEventsPersist(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	if _, err := handle.UpsertAppConsumer(AppConsumer{Name: "myapp", Command: []string{"sh", "-lc", "python app.py"}}); err != nil {
		t.Fatalf("upsert app consumer: %v", err)
	}
	if _, err := handle.UpsertAgentConsumer(AgentConsumer{Name: "claude", AgentID: "claude-code", ConfigPath: "/tmp/.claude.json"}); err != nil {
		t.Fatalf("upsert agent consumer: %v", err)
	}
	data, err := os.ReadFile(store.paths.AuditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "consumer.app.upsert") || !strings.Contains(string(data), "consumer.agent.upsert") {
		t.Fatalf("expected consumer audit events, got %q", string(data))
	}
}
