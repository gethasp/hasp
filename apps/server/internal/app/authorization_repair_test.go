package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestAuthorizationRepairAppearsInTextAndJSONAndRuns(t *testing.T) {
	_, root := setupHintsVault(t)
	args := []string{"--project-root", root, "--env", "KEY=ref_01", "--", "sh", "-c", "test -n \"$KEY\""}
	run := func(args []string) error {
		return executeCommandWithDeps(context.Background(), args, io.Discard, io.Discard, false, &fakeStarter{}, defaultExecDeps())
	}
	err := run(args)
	if err == nil || AppErrorExitCode(err) != exitPermission {
		t.Fatalf("expected permission error, got %v", err)
	}
	for _, jsonMode := range []bool{false, true} {
		var output bytes.Buffer
		writeCLIError(&output, err, jsonMode)
		if !strings.Contains(output.String(), "--grant-project once") || strings.Contains(output.String(), "hasp session grant") {
			t.Fatalf("rendered error omitted supported inline repair: %s", &output)
		}
		if jsonMode {
			var response struct {
				Error appError `json:"error"`
			}
			if e := json.Unmarshal(output.Bytes(), &response); e != nil || response.Error.Code != errCodeGrantDenied {
				t.Fatalf("wrong error envelope: %s (%v)", &output, e)
			}
		}
	}
	if err := run(append([]string{"--grant-project", "once"}, args...)); err != nil {
		t.Fatalf("emitted repair did not run: %v", err)
	}
}
