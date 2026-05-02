package testutil

import (
	"os"
	"path/filepath"
)

// ConfigurePackageTempRoot redirects package-level temporary files into a
// repo-local .testtmp directory and stops git discovery at the package root.
func ConfigurePackageTempRoot(name string) (func(), error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(cwd, ".testtmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(base, "hasp-"+name+"-tests-")
	if err != nil {
		return nil, err
	}
	oldTmp, hadTmp := os.LookupEnv("TMPDIR")
	if err := os.Setenv("TMPDIR", root); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	oldCeiling, hadCeiling := os.LookupEnv("GIT_CEILING_DIRECTORIES")
	ceiling := cwd
	if hadCeiling && oldCeiling != "" {
		ceiling += string(os.PathListSeparator) + oldCeiling
	}
	if err := os.Setenv("GIT_CEILING_DIRECTORIES", ceiling); err != nil {
		if hadTmp {
			_ = os.Setenv("TMPDIR", oldTmp)
		} else {
			_ = os.Unsetenv("TMPDIR")
		}
		_ = os.RemoveAll(root)
		return nil, err
	}
	return func() {
		if hadTmp {
			_ = os.Setenv("TMPDIR", oldTmp)
		} else {
			_ = os.Unsetenv("TMPDIR")
		}
		if hadCeiling {
			_ = os.Setenv("GIT_CEILING_DIRECTORIES", oldCeiling)
		} else {
			_ = os.Unsetenv("GIT_CEILING_DIRECTORIES")
		}
		_ = os.RemoveAll(root)
	}, nil
}

func InitMinimalGitRepo(root string) ([]byte, error) {
	gitDir := filepath.Join(root, ".git")
	for _, dir := range []string{
		filepath.Join(gitDir, "objects"),
		filepath.Join(gitDir, "refs", "heads"),
		filepath.Join(gitDir, "info"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		return nil, err
	}
	config := []byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n")
	if err := os.WriteFile(filepath.Join(gitDir, "config"), config, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(gitDir, "info", "exclude"), nil, 0o600); err != nil {
		return nil, err
	}
	return []byte("Initialized empty Git repository in " + gitDir + "\n"), nil
}
