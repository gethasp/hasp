#!/usr/bin/env python3
import os
import re
import sys
from datetime import datetime, timedelta, timezone


def main() -> int:
    version = sys.argv[1]
    match = re.fullmatch(r"([0-9]+)[.]([0-9]+)[.]([0-9]+)", version)
    if not match:
        raise SystemExit(f"release version cannot be converted to sequence: {version}")
    major, minor, patch = (int(part) for part in match.groups())
    sequence = major * 1_000_000 + minor * 1_000 + patch
    ttl_days = int(os.environ["HASP_RELEASE_METADATA_TTL_DAYS"])
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=ttl_days)
    print(sequence, now.isoformat().replace("+00:00", "Z"), expires.isoformat().replace("+00:00", "Z"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
