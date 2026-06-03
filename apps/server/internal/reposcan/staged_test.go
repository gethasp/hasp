package reposcan

import (
	"context"
	"fmt"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestScanStagedReadsIndexNotWorkingTree pins hasp-8buu: ScanStaged matches on the
// staged blob content (what the commit contains), independent of the working tree.
func TestScanStagedReadsIndexNotWorkingTree(t *testing.T) {
	secret := []byte("AKIAIOSFODNN7EXAMPLEKEY")
	items := []store.Item{{Name: "aws", Value: secret}}
	deps := Deps{
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) {
			return []string{"config.txt", "big.bin"}, nil
		},
		StagedBlobSize: func(ctx context.Context, root, rel string) (int64, error) {
			if rel == "big.bin" {
				return DefaultMaxBytes + 1, nil
			}
			return 64, nil
		},
		ReadStagedBlob: func(ctx context.Context, root, rel string) ([]byte, error) {
			if rel == "config.txt" {
				return []byte("AWS_KEY=" + string(secret)), nil
			}
			t.Fatalf("ReadStagedBlob called for oversized file %q (should have been skipped)", rel)
			return nil, nil
		},
	}

	res, err := ScanStaged(context.Background(), "/repo", items, DefaultMaxBytes, deps)
	if err != nil {
		t.Fatalf("ScanStaged: %v", err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Path != "config.txt" || res.Matches[0].ItemName != "aws" {
		t.Fatalf("expected one match config.txt/aws, got %+v", res.Matches)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Path != "big.bin" {
		t.Fatalf("expected big.bin skipped, got %+v", res.Skipped)
	}
	if res.Walker != "git-staged" {
		t.Fatalf("walker = %q, want git-staged", res.Walker)
	}
}

// TestScanStagedFailsClosedOnReadError ensures a blob read error aborts the scan
// rather than silently passing.
func TestScanStagedFailsClosedOnReadError(t *testing.T) {
	deps := Deps{
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) { return []string{"a"}, nil },
		StagedBlobSize: func(ctx context.Context, root, rel string) (int64, error) { return 10, nil },
		ReadStagedBlob: func(ctx context.Context, root, rel string) ([]byte, error) {
			return nil, fmt.Errorf("staged read failed")
		},
	}
	if _, err := ScanStaged(context.Background(), "/repo", []store.Item{{Name: "x", Value: []byte("secretvalue")}}, DefaultMaxBytes, deps); err == nil {
		t.Fatal("expected ScanStaged to fail closed on a blob read error")
	}
}

func TestScanStagedFailsClosedOnSizeErrorAndDefaultMax(t *testing.T) {
	deps := Deps{
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) { return []string{"a"}, nil },
		StagedBlobSize: func(ctx context.Context, root, rel string) (int64, error) {
			return 0, fmt.Errorf("staged size failed")
		},
	}
	if _, err := ScanStaged(context.Background(), "/repo", nil, 0, deps); err == nil {
		t.Fatal("expected ScanStaged to fail closed on a blob size error")
	}
}

func TestScanStagedFailsClosedOnListError(t *testing.T) {
	deps := Deps{
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) {
			return nil, fmt.Errorf("staged list failed")
		},
	}
	if _, err := ScanStaged(context.Background(), "/repo", nil, DefaultMaxBytes, deps); err == nil {
		t.Fatal("expected ScanStaged to fail closed on a staged list error")
	}
}
