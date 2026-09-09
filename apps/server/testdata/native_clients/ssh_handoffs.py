"""Replay brokered handoffs against a disposable loopback OpenSSH server."""

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time

import replay


def check_cleanup(f, binary):
    marker = f.base / "cleanup-path"
    r = f.run(
        [
            binary,
            "inject",
            "--file",
            "KEY_PATH=@SSH_KEY",
            "--grant-project",
            "session",
            "--",
            "sh",
            "-c",
            'printf "%s" "$KEY_PATH" > "$1"; chmod 500 "$(dirname "$KEY_PATH")"',
            "cleanup",
            str(marker),
        ],
        check=False,
    )
    assert marker.exists(), r.stderr.replace(replay.VALUE, "<synthetic>")
    path = pathlib.Path(marker.read_text())
    try:
        assert path.exists(), "fixture did not force a cleanup failure"
        return {
            "reported": r.returncode != 0 and "cleanup failed" in r.stderr,
            "outcome_reported": "exit code 0" in r.stderr,
            "retry_warning": "before retrying" in r.stderr,
        }
    finally:
        path.parent.chmod(0o700)
        shutil.rmtree(path.parent)


def run(f, previous):
    ssh = shutil.which("ssh")
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    assert ssh and pathlib.Path(sshd).is_file(), "OpenSSH client and server required"
    for name in ("host", "client"):
        f.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "hasp-fixture",
                "-f",
                str(f.base / name),
            ]
        )
    key = (f.base / "client").read_text()
    f.run(
        [
            replay.BINARY,
            "secret",
            "add",
            "--vault-only",
            "--kind",
            "file",
            "--from-stdin",
            "SSH_KEY",
        ],
        key,
    )
    f.run(
        [
            replay.BINARY,
            "project",
            "bind",
            "--hooks=false",
            "--alias",
            "token=CLIENT_TOKEN",
            "--alias",
            "sshkey=SSH_KEY",
            "--json",
        ]
    )
    (f.base / "authorized_keys").write_bytes((f.base / "client.pub").read_bytes())
    (f.base / "client").unlink()
    if previous:
        before = check_cleanup(f, previous)
        assert not before["reported"], (
            "previous binary did not reproduce hidden cleanup"
        )
    assert all(check_cleanup(f, replay.BINARY).values())

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    config = f.base / "sshd_config"
    config.write_text(
        "\n".join(
            [
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {f.base}/host",
                f"PidFile {f.base}/pid",
                f"AuthorizedKeysFile {f.base}/authorized_keys",
                "StrictModes no",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "AllowTcpForwarding no",
                "AllowAgentForwarding no",
                "X11Forwarding no",
                "LogLevel ERROR",
                "",
            ]
        )
    )
    (f.base / "known_hosts").write_text(
        f"[127.0.0.1]:{port} " + (f.base / "host.pub").read_text()
    )
    server = subprocess.Popen(
        [sshd, "-D", "-e", "-f", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                assert server.poll() is None and time.monotonic() < deadline, (
                    "sshd startup failed"
                )
                time.sleep(0.05)
        remote = f.base / "remote-consumer.sh"
        remote.write_text(
            "#!/bin/sh\nset -eu\numask 077\n"
            'credential=$(mktemp "$1/remote.XXXXXX")\n'
            "trap 'rm -f \"$credential\"' EXIT\n"
            "trap 'exit 143' TERM\n"
            'printf "%s" "$credential" > "$1/remote-path"\n'
            'cat > "$credential"\n'
            + shlex.quote(sys.executable)
            + ' "$1/verify.py" "$credential" "$2"\n'
            'case "$3" in term) kill -TERM "$$";; *) exit "$3";; esac\n'
        )
        remote.chmod(0o700)
        (f.base / "verify.py").write_text(
            "import hashlib,pathlib,sys\np=pathlib.Path(sys.argv[1])\n"
            "assert p.stat().st_mode & 0o777 == 0o600\n"
            "assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2]\n"
            'print("remote-consumed")\n'
        )
        local = f.base / "handoff.sh"
        ssh_args = [
            ssh,
            "-F",
            "none",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(f.base / "known_hosts"),
            "-o",
            "ConnectTimeout=5",
        ]
        local.write_text(
            "#!/bin/sh\nset -eu\n"
            + shlex.quote(sys.executable)
            + ' "$1/local.py" "$KEY_PATH" "$1/local-path"\n'
            'if [ "$2" = env ]; then printf "%s" "$TOKEN"; else cat "$KEY_PATH"; fi | '
            + shlex.join(ssh_args)
            + ' -i "$KEY_PATH" -p '
            + str(port)
            + ' 127.0.0.1 "$3"\n'
        )
        local.chmod(0o700)
        (f.base / "local.py").write_text(
            "import pathlib,sys\np=pathlib.Path(sys.argv[1])\n"
            "assert p.stat().st_mode & 0o777 == 0o600\n"
            'assert "project" not in p.parts\n'
            "pathlib.Path(sys.argv[2]).write_text(str(p))\n"
        )
        count = 0
        for delivery, value in (("env", replay.VALUE), ("file", key)):
            for outcome in ("0", "23", "term"):
                command = shlex.join(
                    [
                        str(remote),
                        str(f.base),
                        hashlib.sha256(value.encode()).hexdigest(),
                        outcome,
                    ]
                )
                r = f.run(
                    [
                        replay.BINARY,
                        "inject",
                        "--env",
                        "TOKEN=@CLIENT_TOKEN",
                        "--file",
                        "KEY_PATH=@SSH_KEY",
                        "--grant-project",
                        "session",
                        "--",
                        str(local),
                        str(f.base),
                        delivery,
                        command,
                    ],
                    check=False,
                )
                expected = 143 if outcome == "term" else int(outcome)
                assert (
                    r.returncode == 0
                    if expected == 0
                    else r.returncode != 0
                    and f"command exited with code {expected}" in r.stderr
                ), r.stderr
                assert (
                    "remote-consumed" in r.stdout and value not in r.stdout + r.stderr
                )
                for marker in ("local-path", "remote-path"):
                    assert not pathlib.Path((f.base / marker).read_text()).exists(), (
                        marker
                    )
                count += 1
        r = f.run(
            [
                replay.BINARY,
                "inject",
                "--env",
                "TOKEN=@CLIENT_TOKEN",
                "--file",
                "KEY_PATH=@SSH_KEY",
                "--grant-project",
                "session",
                "--",
                str(local),
                str(f.base),
                "env",
                "cat",
            ]
        )
        assert replay.VALUE not in r.stdout and "REDACTED" in r.stdout
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(server.pid, signal.SIGTERM)
        server.wait(timeout=5)
        server.stderr.close()

    consumer = f.base / "saved-consumer.sh"
    consumer.write_text(
        '#!/bin/sh\nset -eu\ntest -s "$KEY_PATH"\n'
        'printf "%s\\n" "$KEY_PATH" >> '
        + shlex.quote(str(f.base / "saved-paths"))
        + "\nprintf consumer-ok\n"
    )
    consumer.chmod(0o700)
    f.run(
        [
            replay.BINARY,
            "app",
            "connect",
            "handoff",
            "--project-root",
            str(f.root),
            "--cmd",
            str(consumer),
            "--file",
            "KEY_PATH=SSH_KEY",
            "--install=never",
            "--json",
        ]
    )
    for _ in range(2):
        assert "consumer-ok" in f.run([replay.BINARY, "app", "run", "handoff"]).stdout
    paths = (f.base / "saved-paths").read_text().splitlines()
    assert len(set(paths)) == 2 and all(not pathlib.Path(p).exists() for p in paths)
    print(
        json.dumps(
            {
                "ssh": subprocess.check_output(
                    [ssh, "-V"], stderr=subprocess.STDOUT, text=True
                ).strip(),
                "handoffs": count,
                "redaction": "passed",
                "cleanup_failure": "reported",
                "saved_app_fresh_paths": "passed",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hasp-binary", required=True)
    parser.add_argument("--previous-binary")
    args = parser.parse_args()
    replay.BINARY = str(pathlib.Path(args.hasp_binary).resolve(strict=True))
    with replay.Fixture() as fixture:
        run(fixture, args.previous_binary)
