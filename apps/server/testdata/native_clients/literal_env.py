"""Verify literal configuration and reference parity using a disposable vault."""

import argparse
import json
import pathlib
import shlex
import sys

import replay

LITERALS = {"CI": "1", "EMPTY": "", "EXACT": " \n@CLIENT_TOKEN=$HOME=a=b "}


def run(f, previous=None):
    child = f.base / "consume.py"
    receipt = f.base / "receipt.json"
    child.write_text(
        "import json,os,pathlib,sys\n"
        + "assert {k:os.environ[k] for k in "
        + repr(list(LITERALS))
        + "} == "
        + repr(LITERALS)
        + "\n"
        + "assert os.environ['TOKEN'] == "
        + repr(replay.VALUE)
        + "\n"
        + "p=pathlib.Path(os.environ['FILE'])\n"
        + "assert p.read_text() == os.environ['TOKEN']\n"
        + "assert p.stat().st_mode & 0o777 == 0o600\n"
        + "pathlib.Path(sys.argv[1]).write_text(json.dumps({'path':str(p)}))\n"
        + "print('delivery-ok')\n"
        + "print(os.environ['TOKEN'])\n"
    )
    argv = [sys.executable, str(child), str(receipt)]
    flags = [
        part for k, v in LITERALS.items() for part in ("--literal-env", k + "=" + v)
    ]
    mappings = ["--env", "TOKEN=@CLIENT_TOKEN", "--file", "FILE=token"]
    if previous:
        old = f.run([previous, "run", "--dry-run", *flags, "--", "true"], check=False)
        assert old.returncode != 0 and "flag provided but not defined" in old.stderr
        old_app = f.run(
            [
                previous,
                "app",
                "connect",
                "old",
                "--cmd",
                "true",
                "--env",
                "TOKEN=@CLIENT_TOKEN",
            ],
            check=False,
        )
        assert old_app.returncode != 0 and "item not found" in old_app.stderr

    def check_child(command):
        result = f.run(command)
        assert "delivery-ok" in result.stdout and replay.VALUE not in result.stdout
        path = pathlib.Path(json.loads(receipt.read_text())["path"])
        assert not path.exists() and f.root not in path.parents
        return path

    paths = []
    for verb in ("run", "inject"):
        paths.append(
            check_child(
                [
                    replay.BINARY,
                    verb,
                    *mappings,
                    *flags,
                    "--grant-project",
                    "session",
                    "--",
                    *argv,
                ]
            )
        )
    assert paths[0] != paths[1]
    # Literal-only runs still need a project lease.
    literal_only = [
        replay.BINARY,
        "run",
        "--literal-env",
        "CI=1",
        "--",
        "sh",
        "-c",
        'test "$CI" = 1',
    ]
    denied = f.run(literal_only, check=False)
    assert denied.returncode != 0 and "project_lease_required" in denied.stderr
    f.run(literal_only[:2] + ["--grant-project", "once"] + literal_only[2:])

    for bad in (["--env", "CI=1"], ["--file", "FILE=@TYPO"]):
        result = f.run(
            [replay.BINARY, "run", *bad, "--grant-project", "once", "--", "true"],
            check=False,
        )
        assert result.returncode != 0 and "literal-env" in result.stderr
    f.run(
        [replay.BINARY, "secret", "add", "--vault-only", "--from-stdin", "UNEXPOSED"],
        "synthetic-unexposed-value",
    )
    denied = f.run(
        [
            replay.BINARY,
            "run",
            "--env",
            "TOKEN=@UNEXPOSED",
            "--literal-env",
            "CI=1",
            "--grant-project",
            "session",
            "--",
            "true",
        ],
        check=False,
    )
    assert denied.returncode != 0 and "not exposed" in denied.stderr

    # The saved app accepts @names and project aliases and persists literal bytes.
    f.run(
        [
            replay.BINARY,
            "app",
            "connect",
            "literal",
            "--project-root",
            str(f.root),
            "--cmd",
            shlex.join(argv),
            *mappings,
            *flags,
        ]
    )
    for _ in range(2):
        paths.append(check_child([replay.BINARY, "app", "run", "literal"]))
    assert len(set(paths)) == 4
    # Connecting a global app to @NAME remains equivalent to the existing bare-name form.
    f.run(
        [
            replay.BINARY,
            "app",
            "connect",
            "global",
            "--cmd",
            "true",
            "--env",
            "TOKEN=@CLIENT_TOKEN",
        ]
    )

    manifest_path = f.root / ".hasp.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["version"] = "v1"
    manifest["references"] = [{"alias": "token", "item": "CLIENT_TOKEN"}]
    manifest["requirements"] = [
        {"ref": "token", "kind": "kv", "classification": "secret"}
    ]
    manifest["targets"] = [
        {
            "name": "literal",
            "command": argv,
            "literal_env": LITERALS,
            "delivery": [
                {"as": "env", "name": "TOKEN", "ref": "token"},
                {"as": "file", "name": "FILE", "ref": "token"},
            ],
        }
    ]
    manifest_path.write_text(json.dumps(manifest))
    target_run = [
        replay.BINARY,
        "run",
        "--target",
        "literal",
        "--grant-project",
        "session",
    ]
    denied = f.run(target_run, check=False)
    assert denied.returncode != 0 and "review" in denied.stderr, denied.stderr
    f.run([replay.BINARY, "project", "target", "review", "literal"])
    check_child(target_run)
    f.run(
        [
            replay.BINARY,
            "app",
            "connect",
            "target-literal",
            "--project-root",
            str(f.root),
            "--target",
            "literal",
        ]
    )
    check_child([replay.BINARY, "app", "run", "target-literal"])
    manifest["targets"][0]["literal_env"]["EXACT"] = LITERALS["EXACT"].strip()
    manifest_path.write_text(json.dumps(manifest))
    denied = f.run(target_run, check=False)
    assert denied.returncode != 0 and "renewed local review" in denied.stderr
    # Seeding is a snapshot; a later target edit cannot change the saved profile.
    check_child([replay.BINARY, "app", "run", "target-literal"])
    print(
        json.dumps(
            {
                "checks": [
                    "prior CLI and saved-app repro" if previous else "compiled CLI",
                    "exact literal bytes",
                    "mixed CLI env/file delivery and cleanup",
                    "literal-only project lease",
                    "strict missing refs",
                    "unexposed reference denied",
                    "saved app aliases and @names",
                    "target review and saved snapshot",
                ],
                "passed": True,
            }
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hasp-binary", required=True)
    parser.add_argument("--previous-binary")
    args = parser.parse_args()
    replay.BINARY = str(pathlib.Path(args.hasp_binary).resolve())
    with replay.Fixture() as fixture:
        run(fixture, args.previous_binary)


if __name__ == "__main__":
    main()
