package brokerops

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestExecuteOnceGrantsCoverWholeCommand(t *testing.T) {
	for _, policy := range []store.SecretPolicy{store.PolicyAuto, store.PolicySession, store.PolicyAccess} {
		for _, pregranted := range []bool{false, true} {
			name := string(policy) + "/inline"
			if pregranted {
				name = string(policy) + "/pregranted"
			}
			t.Run(name, func(t *testing.T) {
				request := onceExecutionFixture(t, policy)
				if pregranted {
					if _, err := request.Handle.GrantProjectLease(request.BindingID, request.SessionToken, store.GrantOnce, 0); err != nil {
						t.Fatal(err)
					}
					for _, item := range request.Handle.ListItems() {
						if _, err := request.Handle.GrantSecretUse(request.BindingID, request.SessionToken, item.Name, store.GrantOnce, 0, false); err != nil {
							t.Fatal(err)
						}
					}
					request.ProjectGrant, request.SecretGrant = "", ""
				}
				result, err := Execute(context.Background(), request)
				if err != nil {
					t.Fatalf("one command with four env refs, a repeated item, and a file: %v", err)
				}
				if result.RunResult.ExitCode != 0 {
					t.Fatalf("child did not receive the complete mapping: %+v", result.RunResult)
				}
				request.ProjectGrant, request.SecretGrant = "", ""
				if _, err := Execute(context.Background(), request); err == nil {
					t.Fatal("a second command reused consumed once grants")
				}
				marker, err := os.ReadFile(filepath.Join(request.ProjectRoot, "executions"))
				if err != nil || string(marker) != "x" {
					t.Fatalf("child ran more than once: %q, %v", marker, err)
				}
			})
		}
	}
}

func TestExecuteConcurrentOnceGrantsRunOneCompleteCommand(t *testing.T) {
	request := onceExecutionFixture(t, store.PolicySession)
	vault, err := store.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := []ExecutionRequest{request, request}
	for i := range requests {
		requests[i].Handle, err = vault.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	var workers sync.WaitGroup
	for _, req := range requests {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result, err := Execute(context.Background(), req)
			if err == nil && result.RunResult.ExitCode != 0 {
				err = os.ErrInvalid
			}
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("once-grant contenders completed %d commands, want 1", successes)
	}
	marker, err := os.ReadFile(filepath.Join(request.ProjectRoot, "executions"))
	if err != nil || string(marker) != "x" {
		t.Fatalf("child execution count: %q, %v", marker, err)
	}
}

func TestExecuteDeniedMemberDoesNotConsumeOtherOnceGrants(t *testing.T) {
	request := onceExecutionFixture(t, store.PolicySession)
	request.ProjectGrant, request.SecretGrant = "", ""
	if _, err := request.Handle.GrantProjectLease(request.BindingID, request.SessionToken, store.GrantOnce, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := request.Handle.GrantSecretUse(request.BindingID, request.SessionToken, "one", store.GrantOnce, 0, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), request); err == nil {
		t.Fatal("partially approved command ran")
	}
	decision := request.Handle.Authorize(store.AccessRequest{
		Operation: store.OperationRun, BindingID: request.BindingID, SessionToken: request.SessionToken,
		ItemName: "one", Policy: store.PolicySession,
	})
	if !decision.Allowed {
		t.Fatalf("denied batch consumed the approved member's grants: %+v", decision)
	}
	if _, err := os.Stat(filepath.Join(request.ProjectRoot, "executions")); !os.IsNotExist(err) {
		t.Fatalf("denied batch started a child: %v", err)
	}
}

func TestExecuteWithoutReferencesStillRequiresProjectLease(t *testing.T) {
	request := onceExecutionFixture(t, store.PolicySession)
	request.EnvRefs, request.FileRefs = nil, nil
	request.Command = []string{"sh", "-c", "printf x >> executions"}
	request.ProjectGrant, request.SecretGrant = "", ""
	if _, err := Execute(context.Background(), request); err == nil {
		t.Fatal("command without refs ran without project authorization")
	}
	request.ProjectGrant = store.GrantOnce
	result, err := Execute(context.Background(), request)
	if err != nil || result.RunResult.ExitCode != 0 {
		t.Fatalf("inline project grant did not authorize empty mapping: %+v, %v", result, err)
	}
	request.ProjectGrant = ""
	if _, err := Execute(context.Background(), request); err == nil {
		t.Fatal("empty mapping did not consume its project grant")
	}
}

func onceExecutionFixture(t *testing.T, policy store.SecretPolicy) ExecutionRequest {
	t.Helper()
	handle := newBrokeropsHandle(t)
	root := t.TempDir()
	aliases := map[string]string{}
	for _, name := range []string{"one", "two", "three", "four", "file"} {
		kind := store.ItemKindKV
		if name == "file" {
			kind = store.ItemKindFile
		}
		if _, err := handle.UpsertItem(name, kind, []byte("fixture-"+name), store.ItemMetadata{Policy: policy}); err != nil {
			t.Fatal(err)
		}
		aliases[name] = name
	}
	binding, err := handle.UpsertBinding(context.Background(), root, aliases, policy, false)
	if err != nil {
		t.Fatal(err)
	}
	return ExecutionRequest{
		Handle: handle, BindingID: binding.ID, ProjectRoot: root, SessionToken: "one-operation",
		ProjectGrant: store.GrantOnce, SecretGrant: store.GrantOnce, Window: time.Minute,
		EnvRefs:  map[string]string{"ONE": "@one", "TWO": "@two", "THREE": "@three", "FOUR": "@four", "AGAIN": "@one"},
		FileRefs: map[string]string{"FILE": "@file"},
		Command:  []string{"sh", "-c", `test "$ONE" = fixture-one && test "$TWO" = fixture-two && test "$THREE" = fixture-three && test "$FOUR" = fixture-four && test "$AGAIN" = "$ONE" && test "$(cat "$FILE")" = fixture-file && printf x >> executions`},
	}
}
