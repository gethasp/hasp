package reposcan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

var outgoingTestItems = []store.Item{{Name: "test_token", Value: []byte("synthetic-outgoing-credential")}}

func TestScanOutgoingUsesAllSentHistoryAndIgnoresWorkingTree(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			root := newOutgoingRepo(t, format)
			base := outgoingCommit(t, root, "clean.txt", "safe", "base")
			leak := outgoingCommit(t, root, " leading\nfile ", string(outgoingTestItems[0].Value), "leak")
			blob := outgoingGit(t, root, "rev-parse", leak+": leading\nfile ")
			tip := outgoingCommit(t, root, " leading\nfile ", "safe again", "remove leak")
			update := RefUpdate{"refs/heads/main", tip, "refs/heads/main", base}
			res, err := ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{update, update})
			if err != nil || len(res.Matches) != 1 || res.Matches[0].Path != "git:blob:"+blob {
				t.Fatalf("intermediate outgoing leak was missed or duplicated: %+v, %v", res, err)
			}
			// Git replacement objects must not hide the original bytes being sent.
			cleanBlob := outgoingGit(t, root, "rev-parse", tip+": leading\nfile ")
			outgoingGit(t, root, "replace", blob, cleanBlob)
			res, err = ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{update})
			if err != nil || len(res.Matches) != 1 {
				t.Fatalf("replacement hid outgoing leak: %+v, %v", res, err)
			}
			// All history through tip is already remote. Only this clean commit
			// is new; another session's uncommitted draft must not block it.
			next := outgoingCommit(t, root, "clean.txt", "next clean content", "next")
			if err := os.WriteFile(filepath.Join(root, "draft.txt"), outgoingTestItems[0].Value, 0o600); err != nil {
				t.Fatal(err)
			}
			res, err = ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{{"HEAD", next, "refs/heads/main", tip}})
			if err != nil || len(res.Matches) != 0 || res.Walker != "git-outgoing" {
				t.Fatalf("clean outgoing change blocked by unrelated content: %+v, %v", res, err)
			}
			for _, old := range []string{strings.Repeat("0", len(tip)), strings.Repeat("a", len(tip))} {
				res, err = ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{{"HEAD", next, "refs/heads/new", old}})
				if err != nil || len(res.Matches) != 1 {
					t.Fatalf("new branch or unavailable remote tip failed to scan history: %+v, %v", res, err)
				}
			}
			res, err = ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{{"(delete)", strings.Repeat("0", len(tip)), "refs/heads/main", next}})
			if err != nil || len(res.Matches) != 0 || len(res.Skipped) != 0 {
				t.Fatalf("deletion scanned unrelated content: %+v, %v", res, err)
			}
		})
	}
}

func TestScanOutgoingTagsMessagesAndForcedUpdates(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	base := outgoingCommit(t, root, "safe", "safe", "base")
	remote := outgoingCommit(t, root, "safe", "remote content", "remote")
	outgoingGit(t, root, "checkout", "--detach", base)
	tip := outgoingCommit(t, root, "safe", "local content", string(outgoingTestItems[0].Value))
	outgoingGit(t, root, "tag", "-a", "annotated", "-m", string(outgoingTestItems[0].Value))
	tag := outgoingGit(t, root, "rev-parse", "annotated")
	res, err := ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{{"HEAD", tip, "refs/heads/main", remote}, {"refs/tags/annotated", tag, "refs/tags/annotated", strings.Repeat("0", 40)}})
	if err != nil || len(res.Matches) != 2 {
		t.Fatalf("forced update or metadata leaks missed: %+v, %v", res, err)
	}
	kinds := map[string]bool{}
	for _, match := range res.Matches {
		kinds[strings.Split(match.Path, ":")[1]] = true
	}
	if !kinds["commit"] || !kinds["tag"] {
		t.Fatalf("expected commit and tag message matches: %+v", res)
	}
	// Git permits tags pointing directly to a blob.
	blob := outgoingGit(t, root, "rev-parse", tip+":safe")
	res, err = ScanOutgoing(context.Background(), root, []store.Item{{Name: "blob_token", Value: []byte("local content")}}, 0, []RefUpdate{{"refs/tags/blob", blob, "refs/tags/blob", strings.Repeat("0", 40)}})
	if err != nil || len(res.Matches) != 1 || res.Matches[0].Path != "git:blob:"+blob {
		t.Fatalf("blob tag not scanned: %+v, %v", res, err)
	}
}

func TestScanOutgoingFailsClosedAndReportsSkippedObjects(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	tip := outgoingCommit(t, root, "token", string(outgoingTestItems[0].Value), "init")
	zero := strings.Repeat("0", 40)
	for _, oid := range []string{strings.Repeat("b", 40), "--all", tip + "\n--all"} {
		if _, err := ScanOutgoing(context.Background(), root, outgoingTestItems, 0, []RefUpdate{{"HEAD", oid, "refs/heads/main", zero}}); err == nil {
			t.Fatalf("invalid/missing object %q passed", oid)
		}
	}
	res, err := ScanOutgoing(context.Background(), root, outgoingTestItems, 2, []RefUpdate{{"HEAD", tip, "refs/heads/main", zero}})
	if err != nil || len(res.Skipped) != 3 || len(res.Matches) != 0 {
		t.Fatalf("oversized objects not reported: %+v, %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanOutgoing(ctx, root, outgoingTestItems, 0, []RefUpdate{{"HEAD", tip, "refs/heads/main", zero}}); err == nil {
		t.Fatal("cancelled scan passed")
	}
}

func TestReadRefUpdatesRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{"\n", "HEAD --all refs/heads/main 0000\n", "truncated\n", "HEAD " + strings.Repeat("0", 40) + " refs/heads/main " + strings.Repeat("0", 64)} {
		if _, err := ReadRefUpdates(strings.NewReader(input)); err == nil {
			t.Fatalf("malformed input accepted: %q", input)
		}
	}
	zero := strings.Repeat("0", 64)
	got, err := ReadRefUpdates(strings.NewReader("(delete) " + zero + " refs/heads/main " + strings.Repeat("a", 64) + "\n"))
	if err != nil || len(got) != 1 || got[0].LocalRef != "(delete)" {
		t.Fatalf("valid deletion rejected: %+v, %v", got, err)
	}
}

func newOutgoingRepo(t *testing.T, format string) string {
	t.Helper()
	root := t.TempDir()
	outgoingGit(t, root, "init", "--object-format="+format)
	outgoingGit(t, root, "config", "user.name", "Test")
	outgoingGit(t, root, "config", "user.email", "test@example.com")
	return root
}

func outgoingCommit(t *testing.T, root, path, content, message string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	outgoingGit(t, root, "add", "--", path)
	outgoingGit(t, root, "commit", "-m", message)
	return outgoingGit(t, root, "rev-parse", "HEAD")
}

func outgoingGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root, "-c", "core.hooksPath=/dev/null"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
