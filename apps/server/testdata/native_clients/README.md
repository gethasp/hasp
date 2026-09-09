# Native client replays

`replay.py` runs installed Codex CLI, Claude Code, OpenCode, or Pi against a
disposable HASP vault and daemon. Codex, Claude Code, and OpenCode execute tool
requests from a local mock model endpoint. Pi loads the generated package in
its installed SDK and invokes its registered tools, including its real Bash
tool. No model-provider credentials are loaded by the fixture.

Each replay checks transport status, initial project denial, explicit consent
repair, a second tool call, two brokered commands, a staged scan, managed
configuration, shell process protection, plaintext denial, one explicit plaintext grant, and denial
after that grant is consumed. The secret uses the default `auto` policy; the
separate Go authorization tests cover command-wide `once` grants for every
secret policy. The first brokered command checks mixed env/file delivery,
exact literal configuration, and output redaction. The model-driven clients
must advertise all three delivery fields before the fixture calls them.

The fixture stubs the macOS approval dialog response in the operator process.
The CLI still persists and consumes the real scoped grant. This does not test
the native dialog or production code signing. Temporary directories, client
configuration, and the daemon are removed on completion or failure. Model
responses are deterministic, so the replay does not test remote model choices.

Run from the repository root on macOS with Python 3, Node, and the selected
client installed:

```bash
python3 apps/server/testdata/native_clients/replay.py codex-cli --hasp-binary /absolute/path/to/development/hasp
python3 apps/server/testdata/native_clients/replay.py claude-code --hasp-binary /absolute/path/to/development/hasp
python3 apps/server/testdata/native_clients/replay.py opencode --hasp-binary /absolute/path/to/development/hasp
python3 apps/server/testdata/native_clients/replay.py pi --hasp-binary /absolute/path/to/development/hasp
```

The development binary must have the test attestation Team ID configured, as in
the repository's MCP release-gate build. The fixture neither installs the binary
nor alters a live vault or client configuration. Pi's SDK path is inferred from
the installed CLI symlink; use `--pi-module /absolute/path/to/dist/index.js` if
its installation layout differs. The replay prints the installed client version
and completed checks with its results.

Codex uses a separate `CODEX_HOME`, ignores user configuration, and selects the
managed MCP wrapper through CLI overrides. Its MCP environment allowlist pins
the disposable socket and vault settings. The fixture supports direct and
deferred tools using Codex's
[Responses item schema](https://github.com/openai/codex/blob/main/codex-rs/protocol/src/models.rs).
Claude uses a separate configuration directory and strict MCP configuration.
OpenCode uses separate XDG directories and an explicit configuration file;
background title requests do not advance the fixture sequence.

`ssh_handoffs.py` uses a loopback OpenSSH server with temporary host and client
keys. It checks env/file delivery through SSH stdin, redaction, cleanup after
success, failure, and catchable termination, reported local cleanup failure,
and fresh paths on repeated saved-app runs. It does not contact an external
host or read user SSH configuration:

```bash
python3 apps/server/testdata/native_clients/ssh_handoffs.py --hasp-binary /absolute/path/to/development/hasp
```

The SSH replay requires a runnable `sshd` and a non-root account so removing a
directory's write permission can force a cleanup failure. An optional
`--previous-binary` checks that an older binary hides that same failure.

`scan_cost.py` measures complete CLI invocations for working-tree and staged
scans of 500 synthetic files plus the project manifest. It checks matching
coverage, reported counts when available, and a fresh scan after restaging:

```bash
python3 apps/server/testdata/native_clients/scan_cost.py --hasp-binary /absolute/path/to/development/hasp
```

It prints all wall-clock samples and the final scan's phase timings. Compare
the same fixture and machine; these measurements do not predict other vault
sizes, machines, or repository content.

`classification.py` verifies default numeric-ID protection, operator-selected
configuration handling in all three scan modes, preserved brokered links,
exposure/plaintext boundaries, denial from a registered agent process after
clearing guard environment variables, and reset after a value upsert:

```bash
python3 apps/server/testdata/native_clients/classification.py --hasp-binary /absolute/path/to/development/hasp
```

`literal_env.py` verifies exact configuration bytes, mixed env/file delivery,
literal-only project consent, missing and unexposed reference errors, saved-app
`@NAME`/alias support, fresh file paths, and target review after a literal
change. Pass `--previous-binary` to reproduce the old CLI flag and saved-app
reference failures before running the current checks:

```bash
python3 apps/server/testdata/native_clients/literal_env.py --hasp-binary /absolute/path/to/development/hasp
```
