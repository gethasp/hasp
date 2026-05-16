package accessmatrix

import (
	"strconv"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/leases"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func BenchmarkBuildLargeAccessMatrix(b *testing.B) {
	const (
		consumerCount        = 80
		secretCount          = 120
		leasedSecretsPerUser = 30
	)

	now := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	items := make([]store.Item, 0, secretCount)
	for i := 0; i < secretCount; i++ {
		items = append(items, store.Item{
			ID:        "secret-" + strconv.Itoa(i),
			Name:      "SECRET_" + strconv.Itoa(i),
			UpdatedAt: now.Add(-time.Duration(i) * time.Minute),
		})
	}

	appConsumers := make([]store.AppConsumer, 0, consumerCount)
	leasesInput := make([]leases.Lease, 0, consumerCount*leasedSecretsPerUser)
	for consumerIdx := 0; consumerIdx < consumerCount; consumerIdx++ {
		bindings := make([]store.AppBinding, 0, secretCount)
		consumerID := "consumer-" + strconv.Itoa(consumerIdx)
		for secretIdx := 0; secretIdx < secretCount; secretIdx++ {
			bindings = append(bindings, store.AppBinding{SecretName: items[secretIdx].Name})
		}
		for leasedIdx := 0; leasedIdx < leasedSecretsPerUser; leasedIdx++ {
			secret := items[(consumerIdx+leasedIdx)%secretCount]
			leasesInput = append(leasesInput, leases.Lease{
				ID:         "lease-" + strconv.Itoa(consumerIdx) + "-" + strconv.Itoa(leasedIdx),
				SecretID:   secret.ID,
				ConsumerID: consumerID,
				Scope:      "session",
				Status:     "active",
				LastUsedAt: now.Add(-time.Duration(leasedIdx) * time.Second),
				ExpiresAt:  now.Add(45 * time.Second),
			})
		}
		appConsumers = append(appConsumers, store.AppConsumer{Name: consumerID, Bindings: bindings})
	}

	input := Input{
		AppConsumers: appConsumers,
		Items:        items,
		Leases:       leasesInput,
		Now:          now,
	}
	opts := Options{Range: "live", Limit: MaxLimit}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reply, err := Build(input, opts)
		if err != nil {
			b.Fatalf("build matrix: %v", err)
		}
		if reply.Total == 0 || len(reply.Cells) == 0 {
			b.Fatalf("unexpected empty reply: %+v", reply)
		}
	}
}
