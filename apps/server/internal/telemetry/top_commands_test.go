package telemetry

import "testing"

// TestTopRootCommandsRanksByUsage pins hasp-8xrx: when more than `limit` distinct
// commands are recorded, the most-used ones are sent, not the alphabetically
// first ones. "vault" (late in the alphabet, high count) must not be dropped in
// favour of low-count early-alphabet commands.
func TestTopRootCommandsRanksByUsage(t *testing.T) {
	counts := Counts{
		"access": 1, "agent": 1, "app": 1, "audit": 1, "config": 1,
		"docs": 1, "init": 1, "lease": 1, "mcp": 1, "policy": 1,
		"run": 50, "secret": 40, "vault": 30,
	}
	top := topRootCommands(counts, 3)
	if len(top) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(top))
	}
	want := map[string]bool{"run": true, "secret": true, "vault": true}
	for _, c := range top {
		if !want[c.Name] {
			t.Fatalf("top-3 included low-usage command %q (alphabetical leak); got %+v", c.Name, top)
		}
	}
	if top[0].Name != "run" || top[0].Count != 50 {
		t.Fatalf("highest-usage command should be first; got %+v", top)
	}
}
