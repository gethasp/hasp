package cmddispatch

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestWrappersDelegateToRegisteredFunctions(t *testing.T) {
	origPrintHelp := PrintHelpTopicFn
	origIsHelp := IsHelpArgFn
	origWriteJSON := WriteJSONResponseFn
	origRender := RenderJSONOrHumanFn
	origJSON := JSONFlagFn
	origYes := YesFlagFn
	t.Cleanup(func() {
		PrintHelpTopicFn = origPrintHelp
		IsHelpArgFn = origIsHelp
		WriteJSONResponseFn = origWriteJSON
		RenderJSONOrHumanFn = origRender
		JSONFlagFn = origJSON
		YesFlagFn = origYes
	})

	PrintHelpTopicFn = func(w io.Writer, args []string) error {
		if len(args) != 2 || args[0] != "secret" || args[1] != "add" {
			t.Fatalf("unexpected help args: %#v", args)
		}
		_, err := w.Write([]byte("help"))
		return err
	}
	IsHelpArgFn = func(value string) bool { return value == "--help" }
	WriteJSONResponseFn = func(w io.Writer, payload any) error {
		if payload.(string) != "payload" {
			t.Fatalf("unexpected json payload: %#v", payload)
		}
		_, err := w.Write([]byte("json"))
		return err
	}
	RenderJSONOrHumanFn = func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error {
		if !jsonOutput || payload.(string) != "render" {
			t.Fatalf("unexpected render args json=%v payload=%#v", jsonOutput, payload)
		}
		return human(stdout)
	}
	JSONFlagFn = func(context.Context) bool { return true }
	YesFlagFn = func(context.Context) bool { return true }

	var out bytes.Buffer
	if err := PrintHelpTopic(&out, []string{"secret", "add"}); err != nil {
		t.Fatalf("PrintHelpTopic: %v", err)
	}
	if out.String() != "help" {
		t.Fatalf("unexpected help output %q", out.String())
	}
	if !IsHelpArg("--help") {
		t.Fatal("expected help arg delegate")
	}
	out.Reset()
	if err := WriteJSONResponse(&out, "payload"); err != nil {
		t.Fatalf("WriteJSONResponse: %v", err)
	}
	if out.String() != "json" {
		t.Fatalf("unexpected json output %q", out.String())
	}
	out.Reset()
	if err := RenderJSONOrHuman(context.Background(), &out, true, "render", func(w io.Writer) error {
		_, err := w.Write([]byte("human"))
		return err
	}); err != nil {
		t.Fatalf("RenderJSONOrHuman: %v", err)
	}
	if out.String() != "human" {
		t.Fatalf("unexpected render output %q", out.String())
	}
	if !JSONFlag(context.Background()) || !YesFlag(context.Background()) {
		t.Fatal("expected global flag delegates")
	}
}
