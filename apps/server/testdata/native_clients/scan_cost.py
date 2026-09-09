"""Measure compiled CLI scans of a disposable repository with synthetic values."""

import argparse
import json
import pathlib
import statistics
import time

import replay


def run(f, samples):
    for i in range(500):
        (f.root / f"file-{i:04d}.txt").write_text("synthetic safe payload\n" * 400)
    leak = f.root / "file-0499.txt"
    leak.write_text(replay.VALUE)
    f.run(["git", "add", "."])
    expected_bytes = sum(p.stat().st_size for p in f.root.iterdir() if p.is_file())
    results = {}
    for mode, flags in (("working", []), ("staged", ["--staged"])):
        wall = []
        for _ in range(samples):
            start = time.monotonic()
            r = f.run([replay.BINARY, "check-repo", "--json", *flags], check=False)
            wall.append(round((time.monotonic() - start) * 1000, 2))
            payload = json.loads(r.stdout)
            assert r.returncode == 5 and len(payload["matches"]) == 1
            assert payload["complete"] is True
            stats = payload.get("stats")
            if stats:
                assert stats["sources_scanned"] == 501
                assert stats["bytes_scanned"] == expected_bytes
        results[mode] = {
            "wall_ms": wall,
            "median_ms": statistics.median(wall),
            "walker": payload["walker"],
            "last_stats": stats,
        }
    leak.write_text("clean now")
    # Unstaged edits cannot erase an index finding. Restaging must refresh it.
    assert (
        f.run(
            [replay.BINARY, "check-repo", "--staged", "--json"], check=False
        ).returncode
        == 5
    )
    f.run(["git", "add", "."])
    fresh = json.loads(
        f.run([replay.BINARY, "check-repo", "--staged", "--json"]).stdout
    )
    assert not fresh["matches"] and fresh["complete"] is True
    print(
        json.dumps(
            {
                "sources": 501,
                "bytes": expected_bytes,
                "samples": results,
                "fresh_index": "passed",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hasp-binary", required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    assert args.samples > 0, "samples must be positive"
    replay.BINARY = str(pathlib.Path(args.hasp_binary).resolve(strict=True))
    with replay.Fixture() as fixture:
        run(fixture, args.samples)
