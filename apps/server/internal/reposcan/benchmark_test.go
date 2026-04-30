package reposcan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func BenchmarkScanLargeVault(b *testing.B) {
	for _, secretCount := range []int{100, 1000} {
		b.Run(fmt.Sprintf("secrets_%d", secretCount), func(b *testing.B) {
			root := b.TempDir()
			items := benchmarkScanItems(secretCount)
			for i := 0; i < 50; i++ {
				path := filepath.Join(root, fmt.Sprintf("safe-%03d.txt", i))
				if err := os.WriteFile(path, []byte("safe content only\n"), 0o600); err != nil {
					b.Fatalf("write safe file: %v", err)
				}
			}
			leakPath := filepath.Join(root, "leak.txt")
			if err := os.WriteFile(leakPath, append([]byte("prefix "), items[len(items)-1].Value...), 0o600); err != nil {
				b.Fatalf("write leak file: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := Scan(context.Background(), root, items, DefaultMaxFileBytes, DefaultDeps())
				if err != nil {
					b.Fatalf("scan: %v", err)
				}
				if len(result.Matches) == 0 {
					b.Fatal("expected at least one match")
				}
			}
		})
	}
}

func benchmarkScanItems(count int) []store.Item {
	items := make([]store.Item, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, store.Item{
			Name:  fmt.Sprintf("secret_%04d", i),
			Value: []byte(fmt.Sprintf("managed-secret-%04d-value", i)),
		})
	}
	return items
}
