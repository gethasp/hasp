package runner

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// bootstrap sets HASP_HOME to a temp dir so paths.Resolve succeeds.
// It returns the home dir and must be called at the start of each test.
func bootstrapEnvFilterTest(t *testing.T) {
	t.Helper()
	t.Setenv(paths.EnvHome, t.TempDir())
}

// childEnvLines runs /usr/bin/env via Execute and returns the lines of output.
func childEnvLines(t *testing.T, input Input) []string {
	t.Helper()
	if len(input.Command) == 0 {
		input.Command = []string{"/usr/bin/env"}
	}
	result, err := Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return strings.Split(string(result.Stdout), "\n")
}

func TestExecuteStripsHaspSessionTokenFromInheritedEnv(t *testing.T) {
	bootstrapEnvFilterTest(t)
	t.Setenv("HASP_SESSION_TOKEN", "leaked-bearer")
	t.Setenv("HASP_MASTER_PASSWORD", "leaked-master")

	lines := childEnvLines(t, Input{Command: []string{"/usr/bin/env"}})

	for _, line := range lines {
		if line == "HASP_SESSION_TOKEN=leaked-bearer" {
			t.Fatalf("HASP_SESSION_TOKEN=leaked-bearer found in child env; runner must strip it")
		}
		if line == "HASP_MASTER_PASSWORD=leaked-master" {
			t.Fatalf("HASP_MASTER_PASSWORD=leaked-master found in child env; runner must strip it")
		}
	}
}

func TestExecutePreservesHaspHomeAndOtherNonSecretEnv(t *testing.T) {
	bootstrapEnvFilterTest(t)
	t.Setenv("HASP_HOME", "/tmp/hasp-home-fixture")
	t.Setenv("PATH", os.Getenv("PATH"))

	lines := childEnvLines(t, Input{Command: []string{"/usr/bin/env"}})

	foundHome := false
	foundPath := false
	for _, line := range lines {
		if line == "HASP_HOME=/tmp/hasp-home-fixture" {
			foundHome = true
		}
		if strings.HasPrefix(line, "PATH=") {
			foundPath = true
		}
	}
	if !foundHome {
		t.Fatalf("HASP_HOME=/tmp/hasp-home-fixture not found in child env; runner must preserve it")
	}
	if !foundPath {
		t.Fatalf("PATH= not found in child env; runner must preserve PATH")
	}
}

func TestExecuteHonorsExplicitEnvOverridesEvenForStrippedNames(t *testing.T) {
	bootstrapEnvFilterTest(t)
	t.Setenv("HASP_SESSION_TOKEN", "from-parent")

	lines := childEnvLines(t, Input{
		Command: []string{"/usr/bin/env"},
		Env:     map[string]string{"HASP_SESSION_TOKEN": "from-broker"},
	})

	foundBroker := false
	for _, line := range lines {
		if line == "HASP_SESSION_TOKEN=from-parent" {
			t.Fatalf("HASP_SESSION_TOKEN=from-parent found in child env; inherited value must be stripped even when override provided")
		}
		if line == "HASP_SESSION_TOKEN=from-broker" {
			foundBroker = true
		}
	}
	if !foundBroker {
		t.Fatalf("HASP_SESSION_TOKEN=from-broker not found in child env; explicit broker override must win")
	}
}

func TestExecuteEnvOverridesInheritedNonStrippedName(t *testing.T) {
	// hasp-wlkm: pin the documented contract — Input.Env beats the parent
	// env even for plain (non-HASP_) names. Regression guard against any
	// future refactor that prepends instead of appends.
	bootstrapEnvFilterTest(t)
	t.Setenv("HASP_RUNNER_ENV_OVERRIDE_PROBE", "from-parent")

	lines := childEnvLines(t, Input{
		Command: []string{"/usr/bin/env"},
		Env:     map[string]string{"HASP_RUNNER_ENV_OVERRIDE_PROBE": "from-broker"},
	})

	foundOverride := false
	for _, line := range lines {
		if line == "HASP_RUNNER_ENV_OVERRIDE_PROBE=from-parent" {
			t.Fatalf("inherited HASP_RUNNER_ENV_OVERRIDE_PROBE=from-parent leaked when broker override was set")
		}
		if line == "HASP_RUNNER_ENV_OVERRIDE_PROBE=from-broker" {
			foundOverride = true
		}
	}
	if !foundOverride {
		t.Fatalf("broker override HASP_RUNNER_ENV_OVERRIDE_PROBE=from-broker not visible in child env")
	}
}

func TestExecuteDoesNotMutateOsEnviron(t *testing.T) {
	bootstrapEnvFilterTest(t)
	t.Setenv("HASP_SESSION_TOKEN", "still-here")

	childEnvLines(t, Input{Command: []string{"/usr/bin/env"}})

	if got := os.Getenv("HASP_SESSION_TOKEN"); got != "still-here" {
		t.Fatalf("os.Getenv(HASP_SESSION_TOKEN) = %q after Execute; runner must not mutate parent environment", got)
	}
}
