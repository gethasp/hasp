package store

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestConcurrentEnvelopeProcesses(t *testing.T) {
	if root := os.Getenv("HASP_ENVELOPE_PROCESS_ROOT"); root != "" {
		s := newTestStore(t)
		s.paths.StatePath = filepath.Join(root, "vault.json.enc")
		fsyncFileFn = func(*os.File) error {
			ready := filepath.Join(root, fmt.Sprintf("ready-%d", os.Getpid()))
			if err := os.WriteFile(ready, nil, 0o600); err != nil {
				return err
			}
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(root, "go")); err == nil {
					return nil
				}
				time.Sleep(5 * time.Millisecond)
			}
			return fmt.Errorf("parent did not release envelope writers")
		}
		if err := s.writeEnvelopeFile(fileEnvelope{Header: envelopeHeader{Version: formatVersion}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	root := t.TempDir()
	var commands []*exec.Cmd
	for range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentEnvelopeProcesses$")
		cmd.Env = append(os.Environ(), "HASP_ENVELOPE_PROCESS_ROOT="+root)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
		t.Cleanup(func() { _ = cmd.Process.Kill() })
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready, _ := filepath.Glob(filepath.Join(root, "ready-*"))
		if len(ready) == len(commands) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writers did not reach simultaneous write barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(root, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Errorf("concurrent envelope writer: %v", err)
		}
	}
	temps, _ := filepath.Glob(filepath.Join(root, "*.tmp"))
	if len(temps) != 0 {
		t.Fatalf("temporary vault files remain: %v", temps)
	}
	info, err := os.Stat(filepath.Join(root, "vault.json.enc"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("vault permissions: %v, %v", info, err)
	}
}
