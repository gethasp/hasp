package reposcan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestClassificationControlsEveryScanModeWithoutProjectFiltering(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	value := []byte("1234567890123456")
	tip := outgoingCommit(t, root, "leak", string(value), "base")
	if err := os.WriteFile(filepath.Join(root, "staged"), value, 0o600); err != nil {
		t.Fatal(err)
	}
	outgoingGit(t, root, "add", "staged")
	for _, classification := range []store.ItemClassification{"", "unknown", store.ClassificationConfiguration, store.ClassificationConfidential} {
		item := store.Item{Name: "UNEXPOSED_PROJECT_ID", Value: value, Classification: classification}
		for _, duplicate := range []bool{false, true} {
			items := []store.Item{item}
			if duplicate {
				items = append(items, store.Item{Name: "UNEXPOSED_CONFIDENTIAL_COPY", Value: value})
			}
			want := item.Confidential() || duplicate
			for _, scan := range []func() (Result, error){
				func() (Result, error) { return Scan(context.Background(), root, items, 0, Deps{}) },
				func() (Result, error) { return ScanStaged(context.Background(), root, items, 0, Deps{}) },
				func() (Result, error) {
					return ScanOutgoing(context.Background(), root, items, 0, []RefUpdate{{"HEAD", tip, "refs/heads/main", strings.Repeat("0", 40)}})
				},
			} {
				got, err := scan()
				if err != nil || !got.Complete || (len(got.Matches) > 0) != want {
					t.Fatalf("%s duplicate=%t: %+v %v", classification, duplicate, got, err)
				}
				if (got.Stats.ConfigurationItems == 1) != !item.Confidential() {
					t.Fatalf("classification exclusions not reported: %+v", got.Stats)
				}
			}
		}
	}
}
