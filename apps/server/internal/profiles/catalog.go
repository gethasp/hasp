package profiles

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Profile struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Transport            string   `json:"transport"`
	Command              []string `json:"command"`
	ProjectBindingRecipe string   `json:"project_binding_recipe"`
	ApprovalPath         string   `json:"approval_path"`
	SafeInjectPath       string   `json:"safe_inject_path"`
	WriteEnvPath         string   `json:"write_env_path"`
	RegressionFixture    string   `json:"regression_fixture"`
	DocsPath             string   `json:"docs_path"`
}

func LoadDir(dir string) ([]Profile, error) {
	return loadProfilesFS(os.DirFS(dir), ".")
}

func Validate(profile Profile) error {
	if strings.TrimSpace(profile.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(profile.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(profile.Transport) == "" {
		return fmt.Errorf("transport is required")
	}
	if len(profile.Command) == 0 {
		return fmt.Errorf("command is required")
	}
	if strings.TrimSpace(profile.ProjectBindingRecipe) == "" {
		return fmt.Errorf("project_binding_recipe is required")
	}
	if strings.TrimSpace(profile.ApprovalPath) == "" {
		return fmt.Errorf("approval_path is required")
	}
	if strings.TrimSpace(profile.SafeInjectPath) == "" {
		return fmt.Errorf("safe_inject_path is required")
	}
	if strings.TrimSpace(profile.WriteEnvPath) == "" {
		return fmt.Errorf("write_env_path is required")
	}
	if strings.TrimSpace(profile.RegressionFixture) == "" {
		return fmt.Errorf("regression_fixture is required")
	}
	if strings.TrimSpace(profile.DocsPath) == "" {
		return fmt.Errorf("docs_path is required")
	}
	return nil
}

func loadProfilesFS(filesys fs.FS, dir string) ([]Profile, error) {
	entries, err := fs.ReadDir(filesys, dir)
	if err != nil {
		return nil, err
	}
	profiles := make([]Profile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == "release-gates.json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := fs.ReadFile(filesys, path)
		if err != nil {
			return nil, err
		}
		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if err := Validate(profile); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles, nil
}
