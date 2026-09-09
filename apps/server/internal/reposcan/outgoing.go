package reposcan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// RefUpdate is one line from Git's pre-push stdin. Object IDs, not mutable ref
// names or the working tree, define the content being sent.
type RefUpdate struct {
	LocalRef  string
	LocalOID  string
	RemoteRef string
	RemoteOID string
}

var buildOutgoingCommand = outgoingGitCommand

func ReadRefUpdates(input io.Reader) ([]RefUpdate, error) {
	var updates []RefUpdate
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 4 || !validObjectID(fields[1]) || !validObjectID(fields[3]) || len(fields[1]) != len(fields[3]) {
			return nil, fmt.Errorf("invalid pre-push ref update on line %d; expected local-ref local-oid remote-ref remote-oid", len(updates)+1)
		}
		updates = append(updates, RefUpdate{fields[0], strings.ToLower(fields[1]), fields[2], strings.ToLower(fields[3])})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read pre-push ref updates: %w", err)
	}
	return updates, nil
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func zeroObjectID(value string) bool { return strings.Trim(value, "0") == "" }

// ScanOutgoing scans the union of objects reachable from outgoing tips, minus
// objects reachable from remote tips supplied by Git and available locally.
// New refs and unavailable remote tips have no exclusion, so their available
// history is scanned. Ref deletions add no content. Commit and tag messages are
// scanned too; a leak need not occur in a file blob.
func ScanOutgoing(ctx context.Context, root string, items []store.Item, maxBytes int64, updates []RefUpdate) (result Result, err error) {
	defer result.finish(time.Now())
	result.Walker = "git-outgoing"
	result.Complete = true
	defer func() {
		if err != nil {
			result.addIssue(".", "object_scan_failed", err)
		}
	}()
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	var tips, remoteTips []string
	seen := make(map[string]bool)
	for _, update := range updates {
		if !validObjectID(update.LocalOID) || !validObjectID(update.RemoteOID) || len(update.LocalOID) != len(update.RemoteOID) {
			return result, errors.New("invalid pre-push object ID")
		}
		if !zeroObjectID(update.LocalOID) && !seen[update.LocalOID] {
			tips = append(tips, update.LocalOID)
			seen[update.LocalOID] = true
		}
		if !zeroObjectID(update.RemoteOID) && !seen["^"+update.RemoteOID] {
			remoteTips = append(remoteTips, update.RemoteOID)
			seen["^"+update.RemoteOID] = true
		}
	}
	if len(tips) == 0 {
		return result, nil
	}
	batch, err := startObjectBatch(ctx, root)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := batch.close(err != nil); err == nil {
			err = closeErr
		}
	}()
	for _, oid := range remoteTips {
		_, _, exists, infoErr := batch.info(oid)
		if infoErr != nil {
			return result, infoErr
		}
		if exists {
			tips = append(tips, "^"+oid)
		}
	}
	cmd := buildOutgoingCommand(ctx, root, "rev-list", "--objects", "--no-object-names", "--stdin")
	cmd.Stdin = strings.NewReader(strings.Join(tips, "\n") + "\n")
	enumStart := time.Now()
	out, err := cmd.Output()
	result.Stats.EnumerationMS = elapsedMS(enumStart)
	if err != nil {
		return result, fmt.Errorf("enumerate outgoing Git objects: %w", err)
	}
	compiled := result.compile(items)
	objectIDs := strings.Fields(string(out))
	result.Stats.SourcesEnumerated = len(objectIDs)
	for _, oid := range objectIDs {
		if !validObjectID(oid) {
			return result, errors.New("invalid outgoing object ID returned by Git")
		}
		readStart := time.Now()
		kind, size, exists, infoErr := batch.info(oid)
		result.Stats.ReadMS += elapsedMS(readStart)
		if infoErr != nil {
			return result, infoErr
		}
		if !exists {
			return result, fmt.Errorf("outgoing Git object %s is unavailable", oid)
		}
		path := "git:" + kind + ":" + oid
		if size > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: path, Size: size, Reason: "over_max_bytes"})
			continue
		}
		data, readErr := measure(&result.Stats.ReadMS, func() ([]byte, error) { return batch.contents(oid, kind, size) })
		if readErr != nil {
			return result, readErr
		}
		result.match(path, data, compiled)
	}
	return result, nil
}

func outgoingGitCommand(ctx context.Context, root string, args ...string) *exec.Cmd {
	cmd := gitsafe.BuildCommand(ctx, root, append([]string{"--no-replace-objects"}, args...)...)
	// Object inspection must not launch a configured promisor remote or let a
	// local replacement/graft hide the raw history that Git will transmit.
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1", "GIT_GRAFT_FILE=/dev/null")
	return cmd
}

type objectBatch struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func startObjectBatch(ctx context.Context, root string) (*objectBatch, error) {
	cmd := buildOutgoingCommand(ctx, root, "cat-file", "--batch-command")
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, fmt.Errorf("start Git object reader: %w", err)
	}
	return &objectBatch{cmd: cmd, input: input, output: bufio.NewReader(output)}, nil
}

func (b *objectBatch) header(command, oid string) (kind string, size int64, exists bool, err error) {
	if _, err = fmt.Fprintf(b.input, "%s %s\n", command, oid); err != nil {
		return
	}
	line, err := b.output.ReadString('\n')
	if err != nil {
		return "", 0, false, fmt.Errorf("read Git object %s: %w", oid, err)
	}
	fields := strings.Fields(line)
	if len(fields) == 2 && fields[0] == oid && fields[1] == "missing" {
		return "", 0, false, nil
	}
	if len(fields) != 3 || fields[0] != oid {
		return "", 0, false, fmt.Errorf("invalid Git object header for %s", oid)
	}
	switch fields[1] {
	case "blob", "tree", "commit", "tag":
	default:
		return "", 0, false, fmt.Errorf("unknown Git object type for %s", oid)
	}
	size, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return "", 0, false, fmt.Errorf("invalid Git object size for %s", oid)
	}
	return fields[1], size, true, nil
}

func (b *objectBatch) info(oid string) (string, int64, bool, error) {
	return b.header("info", oid)
}

func (b *objectBatch) contents(oid, kind string, size int64) ([]byte, error) {
	actualKind, actualSize, exists, err := b.header("contents", oid)
	if err != nil {
		return nil, err
	}
	if !exists || kind != actualKind || size != actualSize {
		return nil, fmt.Errorf("object %s changed during Git scan", oid)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(b.output, data); err != nil {
		return nil, fmt.Errorf("read Git object %s contents: %w", oid, err)
	}
	if end, err := b.output.ReadByte(); err != nil || end != '\n' {
		return nil, fmt.Errorf("incomplete Git object %s contents", oid)
	}
	return data, nil
}

func (b *objectBatch) close(abort bool) error {
	_ = b.input.Close()
	if abort {
		_ = b.cmd.Process.Kill()
	}
	if err := b.cmd.Wait(); err != nil {
		return fmt.Errorf("read Git objects: %w", err)
	}
	return nil
}
