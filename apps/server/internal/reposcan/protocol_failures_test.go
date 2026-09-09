package reposcan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type failedProtocolIO struct{}

func (failedProtocolIO) Read([]byte) (int, error)  { return 0, io.ErrUnexpectedEOF }
func (failedProtocolIO) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (failedProtocolIO) Close() error              { return nil }

type discardProtocolInput struct{ io.Writer }

func (discardProtocolInput) Close() error { return nil }

func TestObjectBatchRejectsMalformedProtocol(t *testing.T) {
	oid := strings.Repeat("a", 40)
	for _, tc := range []struct{ name, response, want string }{
		{"missing header", "", "read Git object"},
		{"wrong object", strings.Repeat("b", 40) + " blob 1\n", "invalid Git object header"},
		{"short header", oid + " blob\n", "invalid Git object header"},
		{"unknown kind", oid + " unsafe 1\n", "unknown Git object type"},
		{"negative size", oid + " blob -1\n", "invalid Git object size"},
		{"invalid size", oid + " blob x\n", "invalid Git object size"},
		{"missing object", oid + " missing\n", "changed during Git scan"},
		{"changed kind", oid + " tree 1\n", "changed during Git scan"},
		{"changed size", oid + " blob 2\n", "changed during Git scan"},
		{"short contents", oid + " blob 1\n", "contents: EOF"},
		{"missing terminator", oid + " blob 1\nx", "incomplete Git object"},
		{"invalid terminator", oid + " blob 1\nxx", "incomplete Git object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := &objectBatch{input: discardProtocolInput{io.Discard}, output: bufio.NewReader(strings.NewReader(tc.response))}
			if _, err := batch.contents(oid, "blob", 1); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malformed response accepted: %v", err)
			}
		})
	}
	batch := &objectBatch{input: failedProtocolIO{}, output: bufio.NewReader(strings.NewReader(""))}
	if _, _, _, err := batch.info(oid); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed request write: %v", err)
	}
	if _, err := ReadRefUpdates(failedProtocolIO{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("failed push input read: %v", err)
	}
	if validObjectID(strings.Repeat("g", 40)) {
		t.Fatal("non-hex object ID accepted")
	}
}

func protocolCommand(t *testing.T, output string, status int, batch bool) *exec.Cmd {
	t.Helper()
	path := filepath.Join(t.TempDir(), "response")
	if err := os.WriteFile(path, []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `cat "$1"; exit "$2"`
	if batch {
		script = `cat "$1"; cat >/dev/null; exit "$2"`
	}
	return exec.Command("sh", "-c", script, "sh", path, strconv.Itoa(status))
}

func TestIndexParserRejectsPartialAndMalformedRecords(t *testing.T) {
	original := indexGitCommand
	t.Cleanup(func() { indexGitCommand = original })
	oid := strings.Repeat("a", 40)
	record := ":000000 100644 " + strings.Repeat("0", 40) + " " + oid + " A\x00fixture\x00"
	for _, tc := range []struct {
		output, want string
		count        int
	}{
		{"incomplete\x00", "incomplete", 0},
		{"invalid\x00fixture\x00", "invalid", 0},
		{record + "trailing", "unterminated", 1},
		{record, "exit status 23", 1},
	} {
		indexGitCommand = func(context.Context, string, ...string) *exec.Cmd { return protocolCommand(t, tc.output, 23, false) }
		got, err := readIndexObjects(context.Background(), t.TempDir())
		if len(got) != tc.count || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("records=%+v, err=%v", got, err)
		}
	}
}

func TestStagedBatchReportsFailuresWithoutLosingMatches(t *testing.T) {
	originalIndex, originalOutgoing := indexGitCommand, buildOutgoingCommand
	t.Cleanup(func() { indexGitCommand, buildOutgoingCommand = originalIndex, originalOutgoing })
	oid := strings.Repeat("a", 40)
	record := ":000000 100644 " + strings.Repeat("0", 40) + " " + oid + " A\x00fixture\x00"
	value := string(outgoingTestItems[0].Value)
	header := oid + " blob " + strconv.Itoa(len(value)) + "\n"
	for _, step := range []string{"enumeration", "start", "close", "cancel", "contents"} {
		t.Run(step, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			indexGitCommand = func(context.Context, string, ...string) *exec.Cmd {
				status := 0
				if step == "enumeration" {
					status = 23
				}
				return protocolCommand(t, record, status, false)
			}
			buildOutgoingCommand = func(context.Context, string, ...string) *exec.Cmd {
				if step == "start" {
					return exec.Command(filepath.Join(t.TempDir(), "missing-git"))
				}
				response := header + header + value + "\n"
				if step == "contents" {
					return protocolCommand(t, header+header, 0, false)
				}
				if step == "cancel" {
					cancel()
				}
				status := 0
				if step == "close" {
					status = 23
				}
				return protocolCommand(t, response, status, true)
			}
			got, err := scanStagedObjects(ctx, t.TempDir(), outgoingTestItems, 0, nil)
			if err == nil || got.Complete || len(got.Issues) == 0 {
				t.Fatalf("%s passed: %+v, %v", step, got, err)
			}
			if (step == "enumeration" || step == "close") && len(got.Matches) != 1 {
				t.Fatalf("partial scan lost match: %+v", got)
			}
			if step == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

func TestObjectBatchRejectsPipeSetupFailures(t *testing.T) {
	original := buildOutgoingCommand
	t.Cleanup(func() { buildOutgoingCommand = original })
	for _, stdin := range []bool{false, true} {
		buildOutgoingCommand = func(context.Context, string, ...string) *exec.Cmd {
			cmd := exec.Command("sh", "-c", "exit 0")
			if stdin {
				cmd.Stdin = strings.NewReader("")
			} else {
				cmd.Stdout = io.Discard
			}
			return cmd
		}
		if _, err := startObjectBatch(context.Background(), t.TempDir()); err == nil {
			t.Fatal("preconfigured pipe accepted")
		}
	}
}

func TestOutgoingScanReportsObjectProtocolFailures(t *testing.T) {
	original := buildOutgoingCommand
	t.Cleanup(func() { buildOutgoingCommand = original })
	oid, remote := strings.Repeat("a", 40), strings.Repeat("b", 40)
	for _, step := range []string{"remote", "invalid ID", "info", "missing", "contents"} {
		buildOutgoingCommand = func(_ context.Context, _ string, args ...string) *exec.Cmd {
			if args[0] == "rev-list" {
				value := oid
				if step == "invalid ID" {
					value = "invalid"
				}
				return protocolCommand(t, value+"\n", 0, false)
			}
			response := "malformed\n"
			switch step {
			case "missing":
				response = oid + " missing\n"
			case "contents":
				response = oid + " blob 1\nmalformed\n"
			}
			return protocolCommand(t, response, 0, true)
		}
		remoteOID := strings.Repeat("0", 40)
		if step == "remote" {
			remoteOID = remote
		}
		got, err := ScanOutgoing(context.Background(), t.TempDir(), outgoingTestItems, 0, []RefUpdate{{"HEAD", oid, "refs/heads/main", remoteOID}})
		if err == nil || got.Complete || len(got.Issues) == 0 {
			t.Fatalf("%s passed: %+v, %v", step, got, err)
		}
	}
}

func TestScanRejectsCancellationAndGrowthAfterSizeCheck(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "fixture")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, staged := range []bool{false, true} {
		for _, cancelled := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			enumerate := func(context.Context, string) ([]string, error) {
				if cancelled {
					cancel()
				}
				return []string{"fixture"}, nil
			}
			deps := Deps{
				GitLsFiles: enumerate, GitStagedFiles: enumerate,
				GitDeletedFiles: func(context.Context, string) ([]string, error) { return nil, nil },
				ReadFile:        func(string) ([]byte, error) { return []byte("grown"), nil },
				StagedBlobSize:  func(context.Context, string, string) (int64, error) { return 1, nil },
				ReadStagedBlob:  func(context.Context, string, string) ([]byte, error) { return []byte("grown"), nil },
			}
			scan := Scan
			if staged {
				scan = ScanStaged
			}
			got, err := scan(ctx, root, outgoingTestItems, 2, deps)
			cancel()
			if got.Complete {
				t.Fatalf("incomplete scan passed: %+v", got)
			}
			if cancelled && (!errors.Is(err, context.Canceled) || len(got.Issues) != 1) {
				t.Fatalf("cancellation: %+v, %v", got, err)
			}
			if !cancelled && (err != nil || len(got.Skipped) != 1 || got.Skipped[0].Size != 5) {
				t.Fatalf("growth: %+v, %v", got, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Enumerate(ctx, root, Deps{Stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, WalkDir: func(root string, fn fs.WalkDirFunc) error {
		info, err := os.Stat(root)
		if err != nil {
			return err
		}
		return fn(root, fs.FileInfoToDirEntry(info), nil)
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("walk ignored cancellation: %v", err)
	}
	if _, err := DefaultDeps().GitDeletedFiles(context.Background(), filepath.Join(root, "missing")); err == nil {
		t.Fatal("deleted-file enumeration failure ignored")
	}
	item := store.Item{Value: []byte("public-value"), Classification: store.ClassificationConfiguration}
	if HitItem([]byte("public-value"), item) {
		t.Fatal("configuration matched as a secret")
	}
}
