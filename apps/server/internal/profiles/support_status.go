package profiles

import (
	"fmt"
	"sync"
)

const (
	SupportTierFirstClassShipped = "first-class-shipped"
	SupportTierGenericCompatible = "generic-compatible"
	SupportTierConvenienceMode   = "explicit-convenience-mode"

	CompatibilityLabelFirstClass  = "first-class-profile"
	CompatibilityLabelGeneric     = "generic-broker-path"
	CompatibilityLabelConvenience = "convenience-mode"
)

type SupportCheck struct {
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Recovery string `json:"recovery,omitempty"`
}

type SupportStatus struct {
	Profile            Profile                 `json:"profile"`
	SupportTier        string                  `json:"support_tier"`
	CompatibilityLabel string                  `json:"compatibility_label"`
	FirstClass         bool                    `json:"first_class"`
	ReleaseGate        ReleaseGate             `json:"release_gate"`
	Proof              map[string]SupportCheck `json:"proof"`
}

var supportStatusCache sync.Map
var loadSupportCatalogFn = LoadCatalog
var loadSupportGatesFn = LoadReleaseGates

func LoadSupportStatuses() ([]SupportStatus, error) {
	key, keyErr := supportStatusCacheKey()
	if keyErr == nil {
		if cached, ok := supportStatusCache.Load(key); ok {
			return cloneSupportStatuses(cached.([]SupportStatus)), nil
		}
	}
	statuses, err := loadSupportStatusesWith(loadSupportCatalogFn, loadSupportGatesFn)
	if err != nil {
		return nil, err
	}
	if keyErr == nil {
		supportStatusCache.Store(key, cloneSupportStatuses(statuses))
	}
	return statuses, nil
}

func LoadSupportStatus(id string) (SupportStatus, error) {
	statuses, err := LoadSupportStatuses()
	if err != nil {
		return SupportStatus{}, err
	}
	for _, status := range statuses {
		if status.Profile.ID == id {
			return status, nil
		}
	}
	return SupportStatus{}, fmt.Errorf("profile %q not found", id)
}

func loadSupportStatusWith(catalogLoader func() ([]Profile, error), gatesLoader func() (ReleaseGateManifest, error), id string) (SupportStatus, error) {
	statuses, err := loadSupportStatusesWith(catalogLoader, gatesLoader)
	if err != nil {
		return SupportStatus{}, err
	}
	for _, status := range statuses {
		if status.Profile.ID == id {
			return status, nil
		}
	}
	return SupportStatus{}, fmt.Errorf("profile %q not found", id)
}

func loadSupportStatusesWith(catalogLoader func() ([]Profile, error), gatesLoader func() (ReleaseGateManifest, error)) ([]SupportStatus, error) {
	catalog, err := catalogLoader()
	if err != nil {
		return nil, err
	}
	manifest, err := gatesLoader()
	if err != nil {
		return nil, err
	}
	statuses := make([]SupportStatus, 0, len(catalog))
	for _, profile := range catalog {
		statuses = append(statuses, buildSupportStatus(profile, manifest))
	}
	return statuses, nil
}

func buildSupportStatus(profile Profile, manifest ReleaseGateManifest) SupportStatus {
	status := SupportStatus{
		Profile:            profile,
		SupportTier:        SupportTierFirstClassShipped,
		CompatibilityLabel: CompatibilityLabelFirstClass,
		FirstClass:         true,
		Proof:              map[string]SupportCheck{},
	}

	gate, ok := manifest.Profiles[profile.ID]
	if ok {
		status.ReleaseGate = gate
		status.Proof["release_gate"] = SupportCheck{
			Status: "pass",
			Detail: "embedded release gate is present for this shipped profile",
		}
	} else {
		status.FirstClass = false
		status.Proof["release_gate"] = SupportCheck{
			Status:   "fail",
			Detail:   "release gate entry is missing",
			Recovery: "add a release-gates.json entry before claiming first-class profile support",
		}
	}

	if err := verifyDocsSections(profile, manifest.RequiredDocSections); err != nil {
		status.FirstClass = false
		status.Proof["docs"] = SupportCheck{
			Status:   "fail",
			Detail:   err.Error(),
			Recovery: "restore the required support-profile sections in the profile doc",
		}
	} else {
		status.Proof["docs"] = SupportCheck{
			Status: "pass",
			Detail: "profile doc resolves and includes the required release-gate sections",
		}
	}

	if _, err := LoadRegressionFixture(profile); err != nil {
		status.FirstClass = false
		status.Proof["fixture"] = SupportCheck{
			Status:   "fail",
			Detail:   err.Error(),
			Recovery: "restore the regression fixture path for this profile",
		}
	} else {
		status.Proof["fixture"] = SupportCheck{
			Status: "pass",
			Detail: "regression fixture resolves from the embedded profile contract",
		}
	}

	if status.ReleaseGate.EvalTests == nil {
		status.ReleaseGate.EvalTests = []string{}
	}
	if err := verifyEvalTests(status.ReleaseGate); err != nil {
		status.FirstClass = false
		status.Proof["evals"] = SupportCheck{
			Status:   "fail",
			Detail:   err.Error(),
			Recovery: "restore the declared eval coverage before claiming first-class support",
		}
	} else {
		status.Proof["evals"] = SupportCheck{
			Status: "pass",
			Detail: "declared eval tests resolve in the shipped eval suite",
		}
	}

	if err := verifyBenchmarkSuites(status.ReleaseGate); err != nil {
		status.FirstClass = false
		status.Proof["benchmarks"] = SupportCheck{
			Status:   "fail",
			Detail:   err.Error(),
			Recovery: "restore the declared benchmark coverage before claiming first-class support",
		}
	} else {
		status.Proof["benchmarks"] = SupportCheck{
			Status: "pass",
			Detail: "declared benchmark functions resolve in the shipped benchmark suite",
		}
	}

	if status.FirstClass {
		status.Proof["support_tier"] = SupportCheck{
			Status: "pass",
			Detail: "profile qualifies as first-class shipped support",
		}
	} else {
		status.SupportTier = SupportTierGenericCompatible
		status.CompatibilityLabel = CompatibilityLabelGeneric
		status.Proof["support_tier"] = SupportCheck{
			Status:   "warn",
			Detail:   "profile no longer meets the first-class shipped proof bar",
			Recovery: "fix the failing proof dimensions before treating this profile as first-class",
		}
	}

	return status
}

func supportStatusCacheKey() (string, error) {
	dir, err := CatalogDir()
	if err != nil {
		return "", err
	}
	root, err := repoRoot()
	if err != nil {
		root = ""
	}
	return root + "|" + dir, nil
}

func cloneSupportStatuses(in []SupportStatus) []SupportStatus {
	out := make([]SupportStatus, len(in))
	for i, status := range in {
		out[i] = status
		if status.Proof != nil {
			out[i].Proof = map[string]SupportCheck{}
			for key, value := range status.Proof {
				out[i].Proof[key] = value
			}
		}
	}
	return out
}
