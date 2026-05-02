#!/usr/bin/env python3
import json
import sys


def stanza(assets: dict[tuple[str, str], dict], required_by_os: dict[str, set[str]], formula_os: str, asset_os: str) -> str:
    if required_by_os.get(asset_os) != {"arm64", "amd64"}:
        raise SystemExit(f"unsupported Homebrew target set for {asset_os}: {sorted(required_by_os.get(asset_os, set()))}")
    return f'''  on_{formula_os} do
    on_arm do
      url "{assets[(asset_os, "arm64")]["url"]}"
      sha256 "{assets[(asset_os, "arm64")]["sha256"]}"
    end
    on_intel do
      url "{assets[(asset_os, "amd64")]["url"]}"
      sha256 "{assets[(asset_os, "amd64")]["sha256"]}"
    end
  end'''


def main() -> int:
    metadata_path, targets_path = sys.argv[1:3]
    with open(metadata_path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    with open(targets_path, "r", encoding="utf-8") as handle:
        targets = json.load(handle)

    assets = {(item["os"], item["arch"]): item for item in data["artifacts"]}
    required = [(item["goos"], item["goarch"]) for item in targets]
    for key in required:
        if key not in assets:
            raise SystemExit(f"missing release metadata for {key[0]} {key[1]}")

    required_by_os: dict[str, set[str]] = {}
    for goos, goarch in required:
        required_by_os.setdefault(goos, set()).add(goarch)

    print(stanza(assets, required_by_os, "macos", "darwin"))
    print(stanza(assets, required_by_os, "linux", "linux"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
