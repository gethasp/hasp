//go:build unix

package runtime

import (
	"os"
	"os/exec"
	"testing"
)

func TestProcessLineageAndParentPID(t *testing.T) {
	parent, err := processParentPID(os.Getpid())
	if err != nil {
		t.Fatalf("processParentPID: %v", err)
	}
	if parent <= 0 {
		t.Fatalf("expected positive parent pid, got %d", parent)
	}
	lineage, err := processLineage(os.Getpid())
	if err != nil {
		t.Fatalf("processLineage: %v", err)
	}
	if len(lineage) == 0 || lineage[0] != os.Getpid() {
		t.Fatalf("unexpected lineage %+v", lineage)
	}
	if lineage, err := processLineage(0); err != nil || lineage != nil {
		t.Fatalf("expected zero pid to short-circuit, got %+v err=%v", lineage, err)
	}
}

func TestProcessLineageAdditionalBranches(t *testing.T) {
	lockRuntimeSeams(t)

	origExec := lineageExecCommand
	defer func() { lineageExecCommand = origExec }()

	lineageExecCommand = func(_ string, args ...string) *exec.Cmd {
		pid := args[len(args)-1]
		switch pid {
		case "44":
			return exec.Command("sh", "-c", "printf '43'")
		case "43":
			return exec.Command("sh", "-c", "printf '1'")
		default:
			return exec.Command("sh", "-c", "printf '0'")
		}
	}
	lineage, err := processLineage(44)
	if err != nil || len(lineage) != 2 || lineage[0] != 44 || lineage[1] != 43 {
		t.Fatalf("expected synthetic lineage, got %+v err=%v", lineage, err)
	}

	lineageExecCommand = func(_ string, args ...string) *exec.Cmd {
		pid := args[len(args)-1]
		if pid == "50" {
			return exec.Command("sh", "-c", "exit 1")
		}
		return exec.Command("sh", "-c", "printf '0'")
	}
	lineage, err = processLineage(50)
	if err != nil || len(lineage) != 1 || lineage[0] != 50 {
		t.Fatalf("expected partial lineage on parent failure, got %+v err=%v", lineage, err)
	}

	lineageExecCommand = func(_ string, args ...string) *exec.Cmd {
		pid := args[len(args)-1]
		if pid == "60" {
			return exec.Command("sh", "-c", "printf '60'")
		}
		return exec.Command("sh", "-c", "printf ''")
	}
	lineage, err = processLineage(60)
	if err != nil || len(lineage) != 1 || lineage[0] != 60 {
		t.Fatalf("expected self-parent break, got %+v err=%v", lineage, err)
	}
	if parent, err := processParentPID(61); err != nil || parent != 0 {
		t.Fatalf("expected blank parent pid to map to zero, got %d err=%v", parent, err)
	}

	lineageExecCommand = func(_ string, args ...string) *exec.Cmd {
		pid := args[len(args)-1]
		switch pid {
		case "70":
			return exec.Command("sh", "-c", "printf '69'")
		case "69":
			return exec.Command("sh", "-c", "printf '70'")
		default:
			return exec.Command("sh", "-c", "printf '0'")
		}
	}
	lineage, err = processLineage(70)
	if err != nil || len(lineage) != 2 || lineage[0] != 70 || lineage[1] != 69 {
		t.Fatalf("expected cycle break lineage, got %+v err=%v", lineage, err)
	}
}
