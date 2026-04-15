package profiles

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	profilesdata "github.com/gethasp/hasp/apps/server/profiles"
)

const releaseGateFilename = "release-gates.json"

type BenchmarkSuite struct {
	Package   string   `json:"package"`
	Functions []string `json:"functions"`
}

type ReleaseGate struct {
	EvalTests  []string         `json:"eval_tests"`
	Benchmarks []BenchmarkSuite `json:"benchmarks"`
}

type ReleaseGateManifest struct {
	RequiredDocSections []string               `json:"required_doc_sections"`
	Profiles            map[string]ReleaseGate `json:"profiles"`
}

type ContractCheck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type ContractStatus struct {
	ReleaseGate       ContractCheck `json:"release_gate"`
	Docs              ContractCheck `json:"docs"`
	RegressionFixture ContractCheck `json:"regression_fixture"`
	Benchmarks        ContractCheck `json:"benchmarks"`
	Evals             ContractCheck `json:"evals"`
	Ready             bool          `json:"ready"`
}

type RegressionFixture struct {
	Tool         string            `json:"tool"`
	ProjectRoot  string            `json:"project_root,omitempty"`
	SessionToken string            `json:"session_token,omitempty"`
	GrantProject string            `json:"grant_project,omitempty"`
	GrantSecret  string            `json:"grant_secret,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Files        map[string]string `json:"files,omitempty"`
	Command      []string          `json:"command,omitempty"`
}

func LoadCatalog() ([]Profile, error) {
	return loadProfilesFS(profilesdata.FS, ".")
}

func LoadProfile(id string) (Profile, error) {
	return loadProfileWith(LoadCatalog, id)
}

func loadProfileWith(loader func() ([]Profile, error), id string) (Profile, error) {
	profiles, err := loader()
	if err != nil {
		return Profile{}, err
	}
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, nil
		}
	}
	return Profile{}, fmt.Errorf("profile %q not found", id)
}

func LoadReleaseGates() (ReleaseGateManifest, error) {
	return loadReleaseGatesFS(profilesdata.FS, ".")
}

func ReleaseGateForProfile(id string) (ReleaseGate, error) {
	return releaseGateForProfileWith(LoadReleaseGates, id)
}

func releaseGateForProfileWith(loader func() (ReleaseGateManifest, error), id string) (ReleaseGate, error) {
	manifest, err := loader()
	if err != nil {
		return ReleaseGate{}, err
	}
	gate, ok := manifest.Profiles[id]
	if !ok {
		return ReleaseGate{}, fmt.Errorf("release gate missing for %s", id)
	}
	return gate, nil
}

func LoadReleaseGatesFrom(path string) (ReleaseGateManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ReleaseGateManifest{}, err
	}
	return decodeReleaseGates(path, data)
}

func loadReleaseGatesFS(filesys fs.FS, dir string) (ReleaseGateManifest, error) {
	data, err := fs.ReadFile(filesys, filepath.Join(dir, releaseGateFilename))
	if err != nil {
		return ReleaseGateManifest{}, err
	}
	return decodeReleaseGates(filepath.Join(dir, releaseGateFilename), data)
}

func decodeReleaseGates(source string, data []byte) (ReleaseGateManifest, error) {
	var manifest ReleaseGateManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ReleaseGateManifest{}, fmt.Errorf("decode %s: %w", source, err)
	}
	if err := manifest.Validate(); err != nil {
		return ReleaseGateManifest{}, err
	}
	return manifest, nil
}

func (m ReleaseGateManifest) Validate() error {
	if len(m.RequiredDocSections) == 0 {
		return fmt.Errorf("required_doc_sections is required")
	}
	if len(m.Profiles) == 0 {
		return fmt.Errorf("profiles is required")
	}
	for id, gate := range m.Profiles {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("profile id is required")
		}
		if len(gate.EvalTests) == 0 {
			return fmt.Errorf("profile %s requires eval_tests", id)
		}
		if len(gate.Benchmarks) == 0 {
			return fmt.Errorf("profile %s requires benchmarks", id)
		}
		for _, suite := range gate.Benchmarks {
			if strings.TrimSpace(suite.Package) == "" {
				return fmt.Errorf("profile %s benchmark package is required", id)
			}
			if len(suite.Functions) == 0 {
				return fmt.Errorf("profile %s benchmark functions are required for %s", id, suite.Package)
			}
		}
	}
	return nil
}

func LoadRegressionFixture(profile Profile) (RegressionFixture, error) {
	path, err := ResolveRepoPath(profile.RegressionFixture)
	if err != nil {
		return RegressionFixture{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RegressionFixture{}, err
	}
	var fixture RegressionFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return RegressionFixture{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if strings.TrimSpace(fixture.Tool) == "" {
		return RegressionFixture{}, fmt.Errorf("fixture %s missing tool", path)
	}
	return fixture, nil
}

func verifyDocsSections(profile Profile, required []string) error {
	path, err := ResolveRepoPath(profile.DocsPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(data)
	for _, section := range required {
		if !strings.Contains(text, section) {
			return fmt.Errorf("docs for %s missing required section %q", profile.ID, section)
		}
	}
	return nil
}

func verifyBenchmarkSuites(gate ReleaseGate) error {
	for _, suite := range gate.Benchmarks {
		for _, fnName := range suite.Functions {
			if !findBenchmarkFunction(suite.Package, fnName) {
				return fmt.Errorf("benchmark %s missing in %s", fnName, suite.Package)
			}
		}
	}
	return nil
}

func verifyEvalTests(gate ReleaseGate) error {
	for _, testName := range gate.EvalTests {
		if !findEvalTest(testName) {
			return fmt.Errorf("eval test %s missing", testName)
		}
	}
	return nil
}

func ContractStatusForProfile(profile Profile, gate ReleaseGate, requiredDocSections []string) ContractStatus {
	status := ContractStatus{
		ReleaseGate: ContractCheck{OK: true, Detail: "release gate declared"},
		Docs:        contractCheck(verifyDocsSections(profile, requiredDocSections), "docs sections verified"),
		RegressionFixture: contractCheck(
			func() error {
				_, err := LoadRegressionFixture(profile)
				return err
			}(),
			"regression fixture verified",
		),
		Benchmarks: contractCheck(verifyBenchmarkSuites(gate), "benchmark smoke verified"),
		Evals:      contractCheck(verifyEvalTests(gate), "eval coverage verified"),
	}
	status.Ready = status.ReleaseGate.OK && status.Docs.OK && status.RegressionFixture.OK && status.Benchmarks.OK && status.Evals.OK
	return status
}

func contractCheck(err error, success string) ContractCheck {
	if err != nil {
		return ContractCheck{Detail: err.Error()}
	}
	return ContractCheck{OK: true, Detail: success}
}
