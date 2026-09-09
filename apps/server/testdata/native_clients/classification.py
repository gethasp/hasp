"""Verify operator classification with a compiled CLI and disposable values."""

import argparse
import json
import pathlib
import sys

import replay

VALUE = "1234567890123456"


def run(f):
    f.run(
        [replay.BINARY, "secret", "add", "--vault-only", "--from-stdin", "PROJECT_ID"],
        VALUE,
    )
    (f.root / "url.txt").write_text("https://example.com/project/" + VALUE)
    f.run(["git", "add", "."])
    f.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.com",
            "commit",
            "-m",
            "synthetic fixture",
        ]
    )
    oid = f.run(["git", "rev-parse", "HEAD"]).stdout.strip()
    # Keep one changed index blob as well as the committed outgoing object.
    (f.root / "staged.txt").write_text(VALUE)
    f.run(["git", "add", "."])

    def scans(blocked):
        for flags in ([], ["--staged"], ["--pre-push"]):
            updates = (
                f"HEAD {oid} refs/heads/main {'0' * len(oid)}\n"
                if flags == ["--pre-push"]
                else None
            )
            r = f.run(
                [replay.BINARY, "check-repo", "--json", *flags], updates, check=False
            )
            d = json.loads(r.stdout)
            assert r.returncode == (5 if blocked else 0) and d["complete"] is True
            assert bool(d["matches"]) is blocked

    scans(True)
    denied = f.run(
        [
            replay.BINARY,
            "run",
            "--env",
            "ID=@PROJECT_ID",
            "--grant-project",
            "session",
            "--",
            "sh",
            "-c",
            'printf "%s" "$ID"',
        ],
        check=False,
    )
    assert denied.returncode != 0 and VALUE not in denied.stdout
    f.run(
        [
            replay.BINARY,
            "project",
            "bind",
            "--hooks=false",
            "--alias",
            "token=CLIENT_TOKEN",
            "--alias",
            "id=PROJECT_ID",
            "--json",
        ]
    )
    brokered = [
        replay.BINARY,
        "run",
        "--env",
        "ID=@PROJECT_ID",
        "--grant-project",
        "session",
        "--",
        "sh",
        "-c",
        'printf "https://example.com/project/%s" "$ID"',
    ]
    assert VALUE not in f.run(brokered).stdout
    classify = [
        replay.BINARY,
        "secret",
        "classify",
        "PROJECT_ID",
        "--classification",
        "configuration",
        "--json",
    ]
    guarded = dict(f.env, HASP_AGENT_SAFE_MODE="1")
    assert f.run(classify, env=guarded, check=False).returncode != 0
    result = json.loads(f.run(classify).stdout)
    assert result["classification"] == "configuration"
    scans(False)
    assert f.run(brokered).stdout == "https://example.com/project/" + VALUE
    assert (
        f.run(
            [replay.BINARY, "secret", "reveal", "PROJECT_ID"], env=guarded, check=False
        ).returncode
        != 0
    )

    child = f.base / "classification-child.py"
    child.write_text(
        "import json,os,subprocess,sys\n"
        "status=subprocess.run([sys.argv[1],'agent','status','codex-cli','--json'],capture_output=True,text=True,check=True)\n"
        "assert 'daemon_process_tree' in status.stdout\n"
        "env={k:v for k,v in os.environ.items() if k not in ('HASP_AGENT_SAFE_MODE','HASP_SESSION_TOKEN','HASP_AGENT_PROJECT_ROOT','HASP_AGENT_CONSUMER')}\n"
        "r=subprocess.run([sys.argv[1],'secret','classify','PROJECT_ID','--classification','confidential'],env=env,capture_output=True,text=True)\n"
        "assert r.returncode!=0 and 'local operator' in r.stderr\n"
        "print('process-tree-denied')\n"
    )
    assert (
        "process-tree-denied"
        in f.run(
            [
                replay.BINARY,
                "agent",
                "launch",
                "codex-cli",
                "--",
                sys.executable,
                str(child),
                replay.BINARY,
            ]
        ).stdout
    )
    # Classifications are explicit per value write, including idempotent writes.
    f.run(
        [
            replay.BINARY,
            "secret",
            "add",
            "--vault-only",
            "--on-conflict",
            "replace",
            "--from-stdin",
            "PROJECT_ID",
        ],
        VALUE,
    )
    metadata = json.loads(
        f.run([replay.BINARY, "secret", "get", "PROJECT_ID", "--json"]).stdout
    )
    assert metadata["secret"]["classification"] == "confidential"
    scans(True)
    assert VALUE not in f.run(brokered).stdout
    print(
        json.dumps(
            {
                "default_numeric_protection": "passed",
                "operator_configuration": "passed",
                "three_scan_modes": "passed",
                "url_preserved": "passed",
                "exposure_required": "passed",
                "plaintext_grant_required": "passed",
                "cleared_environment_process_guard": "passed",
                "upsert_resets_classification": "passed",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hasp-binary", required=True)
    args = parser.parse_args()
    replay.BINARY = str(pathlib.Path(args.hasp_binary).resolve(strict=True))
    with replay.Fixture() as fixture:
        run(fixture)
