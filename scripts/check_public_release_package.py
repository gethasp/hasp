#!/usr/bin/env python3
import json
import sys
from datetime import datetime


def main() -> int:
    metadata_path, version, targets_path = sys.argv[1:4]
    metadata = json.load(open(metadata_path, encoding="utf-8"))
    targets = json.load(open(targets_path, encoding="utf-8"))
    expected_base = f"https://github.com/gethasp/hasp/releases/download/v{version}"
    if metadata.get("tag_base_url") != expected_base:
        raise SystemExit(f"unexpected tag_base_url: {metadata.get('tag_base_url')}")
    major, minor, patch = (int(part) for part in version.split("."))
    expected_sequence = major * 1_000_000 + minor * 1_000 + patch
    if metadata.get("release_sequence") != expected_sequence:
        raise SystemExit(f"unexpected release_sequence: {metadata.get('release_sequence')}")
    issued_at = datetime.fromisoformat(metadata["issued_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(metadata["expires_at"].replace("Z", "+00:00"))
    if issued_at >= expires_at:
        raise SystemExit("release metadata freshness window is invalid")
    expected = {(target["goos"], target["goarch"]) for target in targets}
    actual = {(item.get("os"), item.get("arch")) for item in metadata.get("artifacts", [])}
    if actual != expected:
        raise SystemExit(f"unexpected artifact targets: {actual}")
    for item in metadata["artifacts"]:
        name = f"hasp_{version}_{item['os']}_{item['arch']}"
        if item.get("name") != name or item.get("tarball") != f"{name}.tar.gz":
            raise SystemExit(f"bad artifact identity: {item}")
        if item.get("url") != f"{expected_base}/{name}.tar.gz":
            raise SystemExit(f"bad artifact url: {item.get('url')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
