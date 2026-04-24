package runtime

import (
	"testing"
	"time"
)

func BenchmarkSessionStoreOpenResolve(b *testing.B) {
	store := NewSessionStore()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, err := store.Open("bench", "/tmp/project", time.Minute, false, "")
		if err != nil {
			b.Fatalf("open session: %v", err)
		}
		if _, ok := store.Resolve(session.Token); !ok {
			b.Fatal("expected resolve to succeed")
		}
		store.Revoke(session.Token)
	}
}

func BenchmarkBrokerOpenSessionRPC(b *testing.B) {
	broker := &brokerRPC{
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}
	request := OpenSessionRequest{
		HostLabel:   "bench",
		ProjectRoot: "/tmp/project",
		TTLSeconds:  int(DefaultSessionTTL.Seconds()),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var reply OpenSessionResponse
		if err := broker.OpenSession(request, &reply); err != nil {
			b.Fatalf("open session: %v", err)
		}
		if reply.SessionToken == "" {
			b.Fatal("expected session token")
		}
	}
}
