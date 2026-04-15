package profiles

import "testing"

func BenchmarkLoadEmbeddedProfilesAndReleaseGates(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profiles, err := LoadCatalog()
		if err != nil {
			b.Fatalf("load profiles: %v", err)
		}
		gates, err := LoadReleaseGates()
		if err != nil {
			b.Fatalf("load release gates: %v", err)
		}
		if len(profiles) == 0 || len(gates.Profiles) == 0 {
			b.Fatal("expected profiles and gates")
		}
	}
}

func BenchmarkLoadSupportStatuses(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statuses, err := LoadSupportStatuses()
		if err != nil {
			b.Fatalf("load support statuses: %v", err)
		}
		if len(statuses) == 0 {
			b.Fatal("expected support statuses")
		}
	}
}
