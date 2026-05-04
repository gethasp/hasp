package audit

import (
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func BenchmarkAppend(b *testing.B) {
	b.Setenv(paths.EnvHome, b.TempDir())
	log, err := New()
	if err != nil {
		b.Fatalf("new audit log: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := log.Append(EventRun, "bench", map[string]any{"n": i}); err != nil {
			b.Fatalf("append: %v", err)
		}
	}
}

func BenchmarkVerifyGrowingChain(b *testing.B) {
	b.Setenv(paths.EnvHome, b.TempDir())
	log, err := New()
	if err != nil {
		b.Fatalf("new audit log: %v", err)
	}
	for i := 0; i < 1000; i++ {
		if _, err := log.Append(EventRun, "bench", map[string]any{"n": i}); err != nil {
			b.Fatalf("append setup: %v", err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := log.Verify(); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

func BenchmarkAppendAfterLargeLog(b *testing.B) {
	b.Setenv(paths.EnvHome, b.TempDir())
	log, err := New()
	if err != nil {
		b.Fatalf("new audit log: %v", err)
	}
	for i := 0; i < 1000; i++ {
		if _, err := log.Append(EventRun, "bench", map[string]any{"n": i}); err != nil {
			b.Fatalf("append setup: %v", err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := log.Append(EventRun, "bench", map[string]any{"n": i}); err != nil {
			b.Fatalf("append: %v", err)
		}
	}
}
