#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: verify-live-release.sh [options] <release-tag>

Verify that a public HASP release is actually live after publication.

Options:
  --timeout <seconds>        How long to wait for hosted endpoints (default: 1800)
  --poll <seconds>           Poll interval while waiting (default: 15)
  --skip-install-script      Do not run the hosted install.sh smoke
  --skip-brew                Do not verify the Homebrew tap
  --brew-fetch               Verify Homebrew by fetching the tap artifact (default)
  --brew-install             Verify Homebrew by installing from the published tap
  --skip-github-release      Do not require the GitHub Release page to exist
EOF
}

timeout_seconds=1800
poll_seconds=15
install_script_smoke=1
brew_mode=fetch
github_release_check=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --poll)
      poll_seconds="${2:-}"
      shift 2
      ;;
    --skip-install-script)
      install_script_smoke=0
      shift
      ;;
    --skip-brew)
      brew_mode=skip
      shift
      ;;
    --brew-fetch)
      brew_mode=fetch
      shift
      ;;
    --brew-install)
      brew_mode=install
      shift
      ;;
    --skip-github-release)
      github_release_check=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

release_tag="$1"
case "$release_tag" in
  v*) ;;
  *)
    printf 'release tag must start with v: %s\n' "$release_tag" >&2
    exit 2
    ;;
esac

version="${release_tag#v}"
if [[ ! "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  printf 'release tag must be semver-like vX.Y.Z: %s\n' "$release_tag" >&2
  exit 2
fi
if [[ ! "$timeout_seconds" =~ ^[0-9]+$ || "$timeout_seconds" -le 0 ]]; then
  printf 'timeout must be a positive integer: %s\n' "$timeout_seconds" >&2
  exit 2
fi
if [[ ! "$poll_seconds" =~ ^[0-9]+$ || "$poll_seconds" -le 0 ]]; then
  printf 'poll interval must be a positive integer: %s\n' "$poll_seconds" >&2
  exit 2
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for live release verification\n' "$1" >&2
    exit 1
  fi
}

need curl
need python3

tmp_dir="$(mktemp -d)"
cleanup() {
  /bin/rm -rf "$tmp_dir"
}
trap cleanup EXIT

release_sequence="$(
  python3 - "$version" <<'PY'
import sys
major, minor, patch = (int(part) for part in sys.argv[1].split("."))
print(major * 1_000_000 + minor * 1_000 + patch)
PY
)"

check_release_json() {
  local label="$1"
  local url="$2"
  local output="$tmp_dir/${label//[^A-Za-z0-9_]/_}.json"
  curl -fsSL "$url" -o "$output" &&
    python3 - "$output" "$version" "$release_sequence" "$release_tag" "$label" <<'PY'
import json
import sys

path, version, sequence, tag, label = sys.argv[1:6]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

got_version = str(payload.get("version") or "")
got_sequence = int(payload.get("release_sequence") or -1)
if got_version != version:
    raise SystemExit(f"{label} returned version {got_version!r}, want {version!r}")
if got_sequence != int(sequence):
    raise SystemExit(f"{label} returned sequence {got_sequence}, want {sequence}")

tag_base_url = str(payload.get("tag_base_url") or "")
if tag_base_url and not tag_base_url.endswith(f"/{tag}"):
    raise SystemExit(f"{label} returned tag_base_url {tag_base_url!r}, want suffix /{tag}")

payload_tag = str(payload.get("tag") or "")
if payload_tag and payload_tag != tag:
    raise SystemExit(f"{label} returned tag {payload_tag!r}, want {tag!r}")
PY
}

check_url_head() {
  local _label="$1"
  local url="$2"
  curl -fsSI "$url" >/dev/null
}

homebrew_tap_repo=""
homebrew_formula=""
canonical_tap_url="https://github.com/gethasp/homebrew-tap.git"
normalize_git_remote_url() {
  local url="$1"
  case "$url" in
    git@github.com:gethasp/homebrew-tap.git)
      printf '%s\n' "$canonical_tap_url"
      ;;
    https://github.com/gethasp/homebrew-tap)
      printf '%s\n' "$canonical_tap_url"
      ;;
    *)
      printf '%s\n' "$url"
      ;;
  esac
}

check_homebrew_tap() {
  if HOMEBREW_NO_AUTO_UPDATE=1 brew tap | grep -Fxq gethasp/tap; then
    :
  else
    HOMEBREW_NO_AUTO_UPDATE=1 brew tap gethasp/tap "$canonical_tap_url" >/dev/null || return 1
  fi
  homebrew_tap_repo="$(brew --repo gethasp/tap)"
  local remote_url=""
  remote_url="$(git -C "$homebrew_tap_repo" remote get-url origin 2>/dev/null || true)"
  if [[ "$(normalize_git_remote_url "$remote_url")" != "$canonical_tap_url" ]]; then
    printf 'gethasp/tap origin is %s, want %s\n' "${remote_url:-<missing>}" "$canonical_tap_url" >&2
    return 1
  fi
  if [[ -d "$homebrew_tap_repo/.git" ]]; then
    git -C "$homebrew_tap_repo" fetch --quiet origin main || return 1
    git -C "$homebrew_tap_repo" checkout --quiet origin/main || return 1
  fi
  homebrew_formula="$homebrew_tap_repo/Formula/hasp.rb"
  if [[ ! -f "$homebrew_formula" ]]; then
    printf 'published Homebrew formula not found: %s\n' "$homebrew_formula" >&2
    return 1
  fi
  grep -F "version \"${version}\"" "$homebrew_formula" >/dev/null || return 1
  grep -F "downloads.gethasp.com/hasp/releases/${release_tag}/" "$homebrew_formula" >/dev/null || return 1
}

wait_for() {
  local label="$1"
  shift
  local deadline=$((SECONDS + timeout_seconds))
  local attempt=1
  until "$@"; do
    if (( SECONDS >= deadline )); then
      printf 'timed out waiting for %s\n' "$label" >&2
      "$@" >&2 || true
      return 1
    fi
    printf 'waiting for %s (attempt %d)\n' "$label" "$attempt"
    attempt=$((attempt + 1))
    sleep "$poll_seconds"
  done
  printf 'verified %s\n' "$label"
}

wait_for "immutable R2 metadata for $release_tag" \
  check_release_json "immutable-r2-metadata" "https://downloads.gethasp.com/hasp/releases/${release_tag}/release-metadata.json"
wait_for "latest R2 metadata for $release_tag" \
  check_release_json "latest-r2-metadata" "https://downloads.gethasp.com/hasp/releases/latest/release-metadata.json"
wait_for "download Worker summary for $release_tag" \
  check_release_json "download-worker-summary" "https://download.gethasp.com/api/release"
wait_for "download Worker signed metadata for $release_tag" \
  check_release_json "download-worker-metadata" "https://download.gethasp.com/api/release-metadata"

if [[ "$github_release_check" == "1" ]]; then
  wait_for "GitHub Release page for $release_tag" \
    check_url_head "github-release" "https://github.com/gethasp/hasp/releases/tag/${release_tag}"
fi

if [[ "$install_script_smoke" == "1" ]]; then
  install_dir="$tmp_dir/install-bin"
  install_script="$tmp_dir/install.sh"
  curl -fsSL https://gethasp.com/install.sh -o "$install_script"
  HASP_INSTALL_DIR="$install_dir" HASP_INSTALL_RUN_SETUP=0 sh "$install_script" >"$tmp_dir/install.log"
  "$install_dir/hasp" version | grep -F "$version" >/dev/null
  printf 'verified hosted install script for %s\n' "$release_tag"
fi

case "$brew_mode" in
  skip)
    ;;
  fetch|install)
    need brew
    wait_for "Homebrew tap for $release_tag" check_homebrew_tap
    HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew fetch --force --formula gethasp/tap/hasp >/dev/null
    if [[ "$brew_mode" == "install" ]]; then
      if brew list --formula --versions hasp >/dev/null 2>&1; then
        installed_version="$(brew list --formula --versions hasp | awk '{print $2; exit}')"
        if [[ "$installed_version" != "$version" ]]; then
          printf 'Homebrew formula hasp is already installed at %s; refusing to replace it in live smoke\n' "$installed_version" >&2
          printf 'Run in a clean environment or uninstall hasp before --brew-install.\n' >&2
          exit 1
        fi
      else
        HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew install --formula gethasp/tap/hasp >/dev/null
      fi
      HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 brew test gethasp/tap/hasp >/dev/null
      hasp version | grep -F "$version" >/dev/null
    fi
    printf 'verified Homebrew tap for %s with mode %s\n' "$release_tag" "$brew_mode"
    ;;
  *)
    printf 'unknown brew mode: %s\n' "$brew_mode" >&2
    exit 2
    ;;
esac

printf 'live release verification passed for %s\n' "$release_tag"
