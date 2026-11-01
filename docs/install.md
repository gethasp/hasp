# Install HASP

Use Homebrew for normal installs on macOS and Linux. Use the packaged release
scripts when you need to verify a tarball by hand or install into a custom
prefix.

## Install with Homebrew

The formula is the released CLI path.

```bash
brew tap gethasp/tap
brew install gethasp/tap/hasp
hasp version
```

If you already added the tap, `brew install gethasp/tap/hasp` is enough.
If `hasp version` still prints an older version after Homebrew upgrades,
another install is earlier on your shell's PATH. Run:

```bash
which -a hasp
```

Remove the older binary, or move Homebrew's bin directory earlier in PATH, then
run `hash -r` in open shells before checking `hasp version` again.

After install, continue with [After Install](after-homebrew.md):

```bash
hasp setup
```

## Install with the script

Use the hosted script when you want the current signed release without adding
the Homebrew tap:

```bash
curl -fsSL https://gethasp.com/install.sh | sh
```

The script prints each install phase, verifies signed release metadata and
artifacts, installs `hasp` to `$HOME/.local/bin/hasp` by default, then prints
the installed version. In an interactive terminal it asks whether to start
`hasp setup` immediately; the default answer is yes.

For automation, set `HASP_INSTALL_RUN_SETUP=0` to skip the prompt or
`HASP_INSTALL_RUN_SETUP=1` to start setup without asking.

## Upgrade with Homebrew

```bash
brew update
brew upgrade hasp
hasp version
```

Run `hasp doctor` after upgrading if a daemon is already running. It reports
CLI and daemon version mismatch.

## Uninstall with Homebrew

```bash
brew uninstall hasp
```

Homebrew removes the formula files. It does not remove your HASP vault,
`HASP_HOME`, repo hooks, app launchers, or audit history. Remove those only when
you are intentionally decommissioning the local install.

## Direct packaged release

Use this path when you downloaded a release tarball and want local signature
verification before install:

```bash
scripts/hasp-verify-release.sh dist/release/hasp_<version>_<os>_<arch>.tar.gz
scripts/hasp-install-release.sh --verify dist/release/hasp_<version>_<os>_<arch>.tar.gz
```

Default install prefix:

```bash
$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>
```

Installed binary:

```bash
$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>/bin/hasp
```

## Upgrade a packaged release

```bash
scripts/hasp-upgrade-release.sh --verify \
  dist/release/hasp_<new-version>_<os>_<arch>.tar.gz \
  "$HOME/.local/share/hasp/hasp_<old-version>_<os>_<arch>"
```

You can also use the CLI upgrade command when you want HASP to fetch and verify
a published release:

```bash
hasp upgrade --version v1.0.1 --yes
```

## Uninstall a packaged release

```bash
scripts/hasp-uninstall-release.sh "$HOME/.local/share/hasp/hasp_<version>_<os>_<arch>"
```

The default uninstall path removes the installed release tree only. Pass
`--remove-hooks-from <repo>` or `--purge-hasp-home <path>` only when that cleanup
is intentional.

Hook cleanup removes only managed hooks that point to this installation. It
restores a saved `.pre-hasp` hook, including its permissions, when one exists.
Unrelated hooks stay in place; a symlink backup stops cleanup with an error.

## Source build

Use source builds for development:

```bash
make build
bin/hasp version
```

Source builds are not the normal user install path.

## Headless macOS setup

Over SSH or in an unattended job, skip Keychain convenience unlock. Use the
noninteractive setup path with a password supplied by the operator's process:

```bash
hasp setup --non-interactive --master-password-env HASP_MASTER_PASSWORD \
  --enable-convenience-unlock never
hasp doctor --project-root /path/to/repo
hasp project doctor --project-root /path/to/repo
```

Set `HASP_MASTER_PASSWORD` through your job's protected input, then remove it
from that job's environment when setup finishes. Do not put it in a repo or
shell startup file. The ordinary interactive path is `hasp setup`.

Keychain convenience unlock is optional. A missing default Keychain, a locked
login Keychain, or denied access does not mean the vault password was rejected.
Setup reports convenience failures separately and applies a 30-second deadline
to each convenience step. A Keychain implementation must honor cancellation;
this deadline does not prove that an OS consent dialog can be dismissed remotely.
Use `never` in unattended sessions to avoid that dependency.

A GUI login and a launchd user session are separate from an SSH login. The CLI
can start its daemon directly; it does not require the macOS app or a LaunchAgent.
If you installed a custom LaunchAgent, inspect it in the intended user's launchd
domain and check its absolute executable path and environment. An agent launched
by launchd may have a different PATH from your terminal.

Use a released binary when diagnosing signing or Keychain trust. Replacing a
binary can change its designated requirement and prompt for renewed access.
Re-enable convenience unlock from the intended signed install in an interactive
session. Do not apply a broad Keychain partition-list change or allow every
application as a workaround. Neither Keychain access nor a launcher grants
project or secret use: target review and broker grants still apply.
