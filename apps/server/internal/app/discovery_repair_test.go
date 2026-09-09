package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretMetadataLeadsToBrokeredUse(t *testing.T) {
	for _, kind := range []store.ItemKind{store.ItemKindKV, store.ItemKindFile} {
		metadata := secretMetadataView{Name: "SCAN_TOKEN", NamedReference: "@SCAN_TOKEN", Kind: kind}
		var out bytes.Buffer
		if err := renderSecretMetadata(&out, metadata, false); err != nil {
			t.Fatal(err)
		}
		command := "hasp run"
		if kind == store.ItemKindFile {
			command = "hasp inject"
		}
		if strings.Contains(out.String(), "--reveal") || !strings.Contains(out.String(), command) || !strings.Contains(out.String(), "@SCAN_TOKEN") || !strings.Contains(out.String(), "hasp secret reveal SCAN_TOKEN") {
			t.Fatalf("metadata has no usable brokered guidance: %s", out.String())
		}
		payload := secretGetJSONPayload(metadata, false, false, nil)
		if example, ok := payload["brokered_example"].(string); !ok || !strings.Contains(out.String(), example) {
			t.Fatalf("JSON and human guidance differ: %+v", payload)
		}
	}
}

func TestSecretMissingNameHintUsesExistingListCommand(t *testing.T) {
	setupHintsVault(t)
	err := Run(context.Background(), []string{"secret", "show", "MISSING"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil || !strings.Contains(classifyAppError(err).Hint, "`hasp secret list`") {
		t.Fatalf("missing secret hint points to unsupported command: %v", classifyAppError(err))
	}
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "list"}, strings.NewReader(""), &out, io.Discard); err != nil || !strings.Contains(out.String(), "api_key") {
		t.Fatalf("suggested list command failed: %s (%v)", out.String(), err)
	}
}

func TestRootCommandConfusionHints(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	for _, tc := range []struct{ input, command string }{
		{"list", "hasp secret list"},
		{"show", "hasp help secret show"},
		{"read", "hasp help secret show"},
		{"retrieve", "hasp help secret show"},
		{"get", "hasp help secret show"},
		{"targets", "hasp project targets"},
		{"hasp_targets", "hasp project targets"},
		{"hasp_list", "hasp project status"},
		{"hasp_check", "hasp check-repo"},
		{"hasp_run", "hasp help run"},
		{"hasp_inject", "hasp help inject"},
	} {
		err := Run(context.Background(), []string{tc.input}, strings.NewReader(""), io.Discard, io.Discard)
		if err == nil || AppErrorExitCode(err) != 2 || !strings.Contains(classifyAppError(err).Hint, "`"+tc.command+"`") {
			t.Fatalf("%s has no runnable repair: %+v", tc.input, classifyAppError(err))
		}
	}
}
