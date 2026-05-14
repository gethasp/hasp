package auditops

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestVerifyAndExportNDJSON(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	log := audit.NewForPaths(paths.Paths{AuditPath: t.TempDir() + "/audit.jsonl"})
	log.WithKey(bytes.Repeat([]byte{1}, sha256.Size))
	if _, err := log.Append(audit.EventRead, "tester", map[string]any{"secret": "prod/db"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	verify, err := Verify(log, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verify.ChainOK || verify.LastVerifiedAt == nil || !verify.LastVerifiedAt.Equal(now) || verify.TotalEntries != 1 {
		t.Fatalf("verify response = %+v", verify)
	}
	if _, err := Verify(nil, now); err == nil {
		t.Fatal("expected nil audit log failure")
	}

	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var out bytes.Buffer
	trailer, err := ExportNDJSON(&out, events, ExportOptions{To: time.Now().UTC().Add(time.Hour)}, log.HMACKey())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if trailer.Count != 1 || trailer.SHA256 == "" || trailer.HMAC == "" || !strings.Contains(out.String(), `"_trailer":true`) {
		t.Fatalf("export trailer = %+v output=%q", trailer, out.String())
	}
	out.Reset()
	trailer, err = ExportNDJSON(&out, events, ExportOptions{From: time.Now().UTC().Add(time.Hour)}, log.HMACKey())
	if err != nil {
		t.Fatalf("filtered export: %v", err)
	}
	if trailer.Count != 0 {
		t.Fatalf("filtered trailer count = %d", trailer.Count)
	}
	if _, err := ExportNDJSON(&out, events, ExportOptions{}, []byte("short")); err == nil {
		t.Fatal("expected invalid trailer key failure")
	}
}

func TestVerifyAndExportResidualBranches(t *testing.T) {
	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")})
	log.WithKey(bytes.Repeat([]byte{1}, sha256.Size))
	if _, err := log.Append(audit.EventRead, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append: %v", err)
	}
	verify, err := Verify(log, time.Time{})
	if err != nil || verify.LastVerifiedAt == nil || verify.LastVerifiedAt.IsZero() {
		t.Fatalf("zero-time verify = %+v err=%v", verify, err)
	}

	brokenPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(brokenPath, []byte("not-json\n"), 0o600); err != nil {
		t.Fatalf("write broken audit: %v", err)
	}
	brokenVerify, err := Verify(audit.NewForPaths(paths.Paths{AuditPath: brokenPath}).WithKey(bytes.Repeat([]byte{1}, sha256.Size)), time.Now().UTC())
	if err != nil {
		t.Fatalf("broken verify should report corruption, not fail: %v", err)
	}
	if brokenVerify.ChainOK || brokenVerify.Error == "" {
		t.Fatalf("broken verify = %+v", brokenVerify)
	}
	if _, err := Verify(audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()}), time.Now().UTC()); err == nil {
		t.Fatal("expected verify read failure")
	}

	eventTime := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{{Timestamp: eventTime, Details: map[string]any{"ok": true}}}
	var out bytes.Buffer
	trailer, err := ExportNDJSON(&out, events, ExportOptions{To: eventTime.Add(-time.Second)}, bytes.Repeat([]byte{2}, sha256.Size))
	if err != nil || trailer.Count != 0 {
		t.Fatalf("to-filter export trailer=%+v err=%v", trailer, err)
	}
	if _, err := ExportNDJSON(io.Discard, []audit.Event{{Details: map[string]any{"bad": make(chan int)}}}, ExportOptions{}, bytes.Repeat([]byte{2}, sha256.Size)); err == nil {
		t.Fatal("expected event marshal failure")
	}
	if _, err := ExportNDJSON(failingAuditWriter{}, events, ExportOptions{}, bytes.Repeat([]byte{2}, sha256.Size)); err == nil {
		t.Fatal("expected event write failure")
	}
	oldMarshal := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal failed") }
	if _, err := ExportNDJSON(io.Discard, nil, ExportOptions{}, bytes.Repeat([]byte{2}, sha256.Size)); err == nil {
		t.Fatal("expected trailer marshal failure")
	}
	jsonMarshal = oldMarshal
	if _, err := ExportNDJSON(failingTrailerWriter{Buffer: new(bytes.Buffer)}, nil, ExportOptions{}, bytes.Repeat([]byte{2}, sha256.Size)); err == nil {
		t.Fatal("expected trailer write failure")
	}
	t.Cleanup(func() { jsonMarshal = oldMarshal })
}

type failingAuditWriter struct{}

func (failingAuditWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type failingTrailerWriter struct {
	*bytes.Buffer
}

func (w failingTrailerWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"_trailer"`)) {
		return 0, errors.New("trailer write failed")
	}
	return w.Buffer.Write(p)
}
