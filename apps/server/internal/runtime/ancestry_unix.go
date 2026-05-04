//go:build unix

package runtime

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

var lineageExecCommand = exec.Command

func processLineage(pid int) ([]int, error) {
	if pid <= 0 {
		return nil, nil
	}
	seen := map[int]struct{}{}
	lineage := make([]int, 0, 8)
	current := pid
	for current > 0 {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		lineage = append(lineage, current)
		parent, err := processParentPID(current)
		if err != nil {
			return lineage, nil
		}
		if parent <= 1 || parent == current {
			break
		}
		current = parent
	}
	return lineage, nil
}

func processParentPID(pid int) (int, error) {
	cmd := lineageExecCommand("ps", "-o", "ppid=", "-p", strconv.Itoa(pid))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("resolve parent pid: %w", err)
	}
	value := strings.TrimSpace(string(bytes.TrimSpace(output)))
	if value == "" {
		return 0, nil
	}
	parent, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse parent pid: %w", err)
	}
	return parent, nil
}
