package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/release"
	apsruntime "github.com/gethasp/hasp/apps/server/internal/runtime"
)

// upgradeDeps gathers the seams the upgrade command needs so tests
// can drive it without standing up a real GitHub release.
type upgradeDeps struct {
	Executable func() (string, error)
	Upgrade    func(ctx context.Context, opts release.UpgradeOptions) (release.UpgradeReport, error)
	IsTerminal func() bool
}

func defaultUpgradeDeps() upgradeDeps {
	return upgradeDeps{
		Executable: os.Executable,
		Upgrade:    release.Upgrade,
		IsTerminal: defaultStderrIsTerminal,
	}
}

func upgradeCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return upgradeCommandWithDeps(ctx, args, stdin, stdout, stderr, defaultUpgradeDeps())
}

func upgradeCommandWithDeps(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps upgradeDeps) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	version := fs.String("version", "", "")
	yes := fs.Bool("yes", false, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp upgrade --version vX.Y.Z [--yes] [--json]")
	}
	target := strings.TrimSpace(*version)
	if target == "" {
		return errors.New("hasp upgrade: --version is required (find releases at https://github.com/gethasp/hasp/releases)")
	}

	pinned := release.PinnedPublicKeys()
	if len(pinned) == 0 {
		return errors.New("hasp upgrade: this build has no embedded release-signing keys; rebuild from a signed release to enable self-upgrade")
	}

	currentVersion := apsruntime.VersionString()
	if err := release.CheckUpgrade(currentVersion, target); err != nil {
		return err
	}

	exePath, err := deps.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}

	if !*yes && !globalFlagsFromContext(ctx).yes {
		if !deps.IsTerminal() {
			return errors.New("hasp upgrade: refusing to upgrade non-interactively without --yes; pass --yes to skip confirmation, or run from a terminal")
		}
		if !confirmUpgrade(stdin, stderr, currentVersion, target, exePath) {
			return errors.New("hasp upgrade: aborted by user")
		}
	}

	progress := io.Discard
	if !*jsonOutput {
		progress = stderr
	}
	report, err := deps.Upgrade(ctx, release.UpgradeOptions{
		CurrentVersion: currentVersion,
		TargetVersion:  target,
		TargetPath:     exePath,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		Pinned:         pinned,
		Progress:       progress,
	})
	if err != nil {
		return err
	}

	payload := map[string]any{
		"from_version": report.FromVersion,
		"to_version":   report.ToVersion,
		"signer_key":   report.SignerKey,
		"installed_at": report.InstalledAt,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "Upgraded %s → %s (signed by %s…)\n", report.FromVersion, report.ToVersion, report.SignerKey[:16])
		return err
	})
}

func confirmUpgrade(stdin io.Reader, stderr io.Writer, current, target, path string) bool {
	if stdin == nil {
		return false
	}
	fmt.Fprintf(stderr,
		"hasp upgrade plan:\n  from:    %s\n  to:      %s\n  binary:  %s\n  source:  %s/v%s/\n",
		current, target, path, release.DefaultReleaseURLBase, strings.TrimPrefix(target, "v"))
	fmt.Fprintf(stderr,
		"\nThe new tarball is fetched over HTTPS, its KEYS file is verified\n"+
			"against the embedded trust roots, and the tarball signature is\n"+
			"checked against that KEYS file before the binary is replaced.\n"+
			"\nProceed? [y/N] ")
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}
