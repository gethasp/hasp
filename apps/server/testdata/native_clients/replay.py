"""Exercise installed clients with synthetic secrets and local model responses."""

import argparse
import contextlib
import http.server
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

BINARY = None
VALUE = "synthetic-native-client-secret-value"


class Fixture:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hasp-native-", dir="/tmp")
        self.daemon = None
        try:
            return self.start()
        except BaseException:
            self.__exit__()
            raise

    def start(self):
        self.base = pathlib.Path(self.temp.name).resolve()
        self.root = self.base / "project"
        self.root.mkdir()
        self.home = self.base / "vault"
        self.bin = self.base / "bin"
        self.bin.mkdir()
        (self.bin / "hasp").symlink_to(BINARY)
        self.env = {
            k: v
            for k, v in os.environ.items()
            if k
            in ("PATH", "SHELL", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME", "HOME")
        }
        self.env.update(
            PATH=str(self.bin) + os.pathsep + self.env["PATH"],
            HASP_HOME=str(self.home),
            HASP_SOCKET=str(self.base / "daemon.sock"),
            HASP_MASTER_PASSWORD="Synthetic client test password!",
            HASP_SESSION_TOKEN="",
            HASP_AGENT_SAFE_MODE="",
            HASP_AGENT_PROJECT_ROOT="",
            HASP_AGENT_CONSUMER="",
            HASP_TEST="1",
            HASP_TELEMETRY_DISABLED="1",
            CODEX_HOME=str(self.base / "codex"),
            CLAUDE_CONFIG_DIR=str(self.base / "claude"),
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
            PI_CODING_AGENT_DIR=str(self.base / "pi"),
            PI_OFFLINE="1",
            PI_TELEMETRY="0",
            XDG_CONFIG_HOME=str(self.base / "config"),
            XDG_DATA_HOME=str(self.base / "data"),
            XDG_CACHE_HOME=str(self.base / "cache"),
            XDG_STATE_HOME=str(self.base / "state"),
            OPENCODE_DISABLE_MODELS_FETCH="true",
            OPENCODE_DISABLE_AUTOUPDATE="true",
            OPENCODE_DISABLE_DEFAULT_PLUGINS="true",
            OPENCODE_DISABLE_CLAUDE_CODE="true",
            OPENCODE_CONFIG=str(self.base / "opencode.json"),
        )
        self.run([BINARY, "init"])
        self.run(
            [BINARY, "secret", "add", "--vault-only", "--from-stdin", "CLIENT_TOKEN"],
            VALUE,
        )
        self.run(["git", "init"])
        self.run(
            [
                BINARY,
                "project",
                "bind",
                "--project-root",
                str(self.root),
                "--hooks=false",
                "--alias",
                "token=CLIENT_TOKEN",
                "--json",
            ]
        )
        self.run(
            [BINARY, "project", "init", "--project-root", str(self.root), "--json"]
        )
        self.daemon = subprocess.Popen(
            [BINARY, "daemon", "serve"],
            env=self.env,
            cwd=self.root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while not (self.base / "daemon.sock").exists():
            assert self.daemon.poll() is None and time.monotonic() < deadline, (
                "daemon startup failed"
            )
            time.sleep(0.02)
        return self

    def __exit__(self, *exc):
        if self.daemon is not None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait()
        self.temp.cleanup()

    def run(self, args, input=None, env=None, timeout=40, check=True):
        child = subprocess.Popen(
            args,
            cwd=self.root,
            env=env or self.env,
            stdin=subprocess.PIPE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = child.communicate(input, timeout=timeout)
        finally:
            # The fixture owns this group, including MCP children left on exit.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        r = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
        if check and r.returncode:
            raise RuntimeError(
                str(args[:3]) + ": " + r.stderr.replace(VALUE, "<synthetic>")[:2000]
            )
        return r

    def launch(self, client, args):
        token = self.base / "operator-token"
        wrapper = self.base / "launch.py"
        wrapper.write_text(
            'import os,sys\nfd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\nos.write(fd,os.environ["HASP_SESSION_TOKEN"].encode())\nos.close(fd)\nos.execvp(sys.argv[2],sys.argv[2:])\n'
        )
        return [
            BINARY,
            "agent",
            "launch",
            client,
            "--",
            sys.executable,
            str(wrapper),
            str(token),
            *args,
        ]

    def grant(self):
        # Only the dialog response is stubbed. The CLI writes and consumes a
        # real item/action/session-scoped grant in the disposable vault.
        operator = self.base / "operator-bin"
        operator.mkdir(exist_ok=True)
        dialog = operator / "osascript"
        dialog.write_text(
            "#!"
            + sys.executable
            + '\nimport sys\nassert sys.argv[1]=="-e"\nassert "Allow one-time reveal of CLIENT_TOKEN" in sys.argv[2]\nassert "hasp-native-" in sys.argv[2]\n'
        )
        dialog.chmod(0o700)
        env = dict(
            self.env,
            HASP_SESSION_TOKEN=(self.base / "operator-token").read_text(),
            PATH=str(operator) + os.pathsep + self.env["PATH"],
        )
        self.run(
            [
                BINARY,
                "session",
                "grant-plaintext",
                "--item",
                "CLIENT_TOKEN",
                "--action",
                "reveal",
                "--json",
            ],
            env=env,
        )


def flatten(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(flatten(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(
            flatten(v)
            for k, v in value.items()
            if k in ("content", "text", "output", "result", "error", "message")
        )
    return ""


class Model:
    def __init__(self, fixture, client):
        self.f = fixture
        self.client = client
        self.sent = []
        self.seen = {}
        self.failure = None
        self.i = 0
        self.approval_key = uuid.uuid4().hex
        self.searches = 0
        root = str(fixture.root)
        self.actions = [
            ("hasp_status", {}),
            ("hasp_list", {"project_root": root}),
            ("hasp_list", {"project_root": root, "grant_project": "session"}),
            ("hasp_targets", {"project_root": root}),
            (
                "hasp_run",
                {
                    "project_root": root,
                    "env": {"TOKEN": "@CLIENT_TOKEN"},
                    "files": {"TOKEN_FILE": "@CLIENT_TOKEN"},
                    "literal_env": {
                        "CI": "1",
                        "EMPTY": "",
                        "EXACT": " @TOKEN=$HOME=a=b ",
                    },
                    "grant_secret": "once",
                    "command": [
                        "sh",
                        "-c",
                        'test -n "$TOKEN" && test "$(cat "$TOKEN_FILE")" = "$TOKEN" '
                        '&& test "$CI" = 1 && test "${EMPTY+x}" = x && test -z "$EMPTY" '
                        "&& test \"$EXACT\" = ' @TOKEN=$HOME=a=b ' "
                        '&& printf "brokered-ok %s" "$TOKEN"',
                    ],
                },
            ),
            (
                "hasp_run",
                {
                    "project_root": root,
                    "env": {"TOKEN": "@CLIENT_TOKEN"},
                    "grant_secret": "once",
                    "command": ["sh", "-c", "printf second-brokered-ok"],
                },
            ),
            (
                "hasp_check",
                {"project_root": root, "staged": True},
            ),
            (
                "shell",
                {"command": f"{shlex.quote(BINARY)} agent status {client} --json"},
            ),
            ("shell", {"command": shlex.quote(BINARY) + " secret reveal CLIENT_TOKEN"}),
            ("grant", {}),
            ("shell", {"command": shlex.quote(BINARY) + " secret reveal CLIENT_TOKEN"}),
            ("shell", {"command": shlex.quote(BINARY) + " secret reveal CLIENT_TOKEN"}),
        ]

    def collect(self, body):
        if self.client == "codex-cli":
            for item in body.get("input", []):
                if item.get("type") == "function_call_output":
                    self.seen[item.get("call_id")] = flatten(item.get("output"))
        elif self.client == "claude-code":
            for message in body.get("messages", []):
                for item in (
                    message.get("content", [])
                    if isinstance(message.get("content"), list)
                    else []
                ):
                    if item.get("type") == "tool_result":
                        self.seen[item["tool_use_id"]] = flatten(item["content"])
        else:
            for message in body.get("messages", []):
                if message.get("role") == "tool":
                    self.seen[message.get("tool_call_id")] = flatten(
                        message.get("content")
                    )

    def next(self, body):
        self.collect(body)
        if not body.get("tools"):
            return None
        if self.failure or self.i >= len(self.actions):
            return None
        name, args = self.actions[self.i]
        self.i += 1
        if name == "grant":
            self.f.grant()
            return self.next(body)
        candidates = []
        available = list(body.get("tools", []))
        # Codex sends discovered schemas in tool_search_output/additional_tools.
        for item in body.get("input", []):
            if item.get("type") in ("tool_search_output", "additional_tools"):
                available.extend(item.get("tools", []))
        for tool in available:
            inner = tool.get("function", tool)
            if inner.get("type") == "namespace":
                candidates.extend(
                    dict(t, namespace=inner.get("name")) for t in inner.get("tools", [])
                )
            else:
                candidates.append(inner)
        selected = None
        for tool in candidates:
            n = tool.get("name", "")
            if n.endswith(name) or (
                name == "shell"
                and n.lower() in ("bash", "shell", "shell_command", "exec_command")
            ):
                selected = tool
                break
        if selected is None:
            if (
                self.client == "codex-cli"
                and self.searches < 5
                and any(t.get("type") == "tool_search" for t in available)
            ):
                self.i -= 1
                self.searches += 1
                return (
                    "search_" + str(self.searches),
                    "tool_search",
                    {"query": "hasp " + name, "limit": 20},
                    None,
                )
            raise AssertionError(
                "missing "
                + name
                + "; offered "
                + ",".join(t.get("name", t.get("type", "")) for t in candidates)
            )
        if name == "hasp_run":
            props = selected.get("parameters", selected.get("input_schema", {})).get(
                "properties", {}
            )
            assert {"env", "files", "literal_env"} <= props.keys(), (
                "execution schema missing a delivery channel"
            )
        if name == "shell":
            n = selected["name"]
            props = selected.get("parameters", selected.get("input_schema", {})).get(
                "properties", {}
            )
            if "cmd" in props:
                args = {
                    "cmd": args["command"],
                    "workdir": str(self.f.root),
                    "max_output_tokens": 3000,
                    "login": False,
                }
            elif props.get("command", {}).get("type") == "array":
                args = {
                    "command": ["sh", "-c", args["command"]],
                    "workdir": str(self.f.root),
                }
            elif n.lower() == "bash":
                args = {**args, "description": "Verify HASP fixture protection"}
        callid = "call_" + str(len(self.sent))
        self.sent.append((callid, name))
        return callid, selected["name"], args, selected.get("namespace")

    def verify(self):
        if self.failure:
            raise AssertionError(self.failure)
        assert self.i == len(self.actions), (self.i, len(self.actions))
        values = [self.seen.get(id, "") for id, _ in self.sent]
        assert len(values) == 11, len(values)
        assertions = [
            ("transport", re.search(r'"connection"\s*:\s*"connected"', values[0])),
            ("initial-consent", "project_lease_required" in values[1]),
            ("grant-repair", "CLIENT_TOKEN" in values[2]),
            (
                "second-call",
                "project_lease_required" not in values[3] and bool(values[3]),
            ),
            ("brokered-run", "brokered-ok" in values[4] and VALUE not in values[4]),
            ("second-brokered-run", "second-brokered-ok" in values[5]),
            ("staged-check", "git-staged" in values[6]),
            (
                "shell-process",
                "daemon_process_tree" in values[7] and str(self.f.root) in values[7],
            ),
            ("managed-configuration", re.search(r'"configured"\s*:\s*true', values[7])),
            (
                "plaintext-denied",
                "plaintext secret access is blocked" in values[8]
                and VALUE not in values[8],
            ),
            ("explicit-grant", VALUE in values[9]),
            (
                "plaintext-once",
                "plaintext secret access is blocked" in values[10]
                and VALUE not in values[10],
            ),
        ]
        failed = [n for n, ok in assertions if not ok]
        if failed:
            print(
                json.dumps(
                    {
                        "client": self.client,
                        "failed": failed,
                        "outputs": [
                            v.replace(VALUE, "<synthetic>")[:1800] for v in values
                        ],
                    }
                )
            )
            raise AssertionError("native replay failed")
        return {
            "client": self.client,
            "checks": [n for n, ok in assertions],
            "calls": len(values),
        }


@contextlib.contextmanager
def serve(model):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/fixture/approve":
                    if body.get("key") != model.approval_key:
                        self.send_response(403)
                        self.end_headers()
                        return
                    model.f.grant()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                if self.path.endswith("/count_tokens"):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"input_tokens":1}')
                    return
                action = model.next(body)
                events = []
                if model.client == "claude-code":
                    message = {
                        "id": "msg_" + uuid.uuid4().hex,
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-4-5",
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 1, "output_tokens": 1},
                    }
                    events.append(
                        ("message_start", {"type": "message_start", "message": message})
                    )
                    if action:
                        callid, name, args, namespace = action
                        events.extend(
                            [
                                (
                                    "content_block_start",
                                    {
                                        "type": "content_block_start",
                                        "index": 0,
                                        "content_block": {
                                            "type": "tool_use",
                                            "id": callid,
                                            "name": name,
                                            "input": {},
                                        },
                                    },
                                ),
                                (
                                    "content_block_delta",
                                    {
                                        "type": "content_block_delta",
                                        "index": 0,
                                        "delta": {
                                            "type": "input_json_delta",
                                            "partial_json": json.dumps(args),
                                        },
                                    },
                                ),
                            ]
                        )
                    else:
                        events.extend(
                            [
                                (
                                    "content_block_start",
                                    {
                                        "type": "content_block_start",
                                        "index": 0,
                                        "content_block": {"type": "text", "text": ""},
                                    },
                                ),
                                (
                                    "content_block_delta",
                                    {
                                        "type": "content_block_delta",
                                        "index": 0,
                                        "delta": {
                                            "type": "text_delta",
                                            "text": "Fixture complete.",
                                        },
                                    },
                                ),
                            ]
                        )
                    events.extend(
                        [
                            (
                                "content_block_stop",
                                {"type": "content_block_stop", "index": 0},
                            ),
                            (
                                "message_delta",
                                {
                                    "type": "message_delta",
                                    "delta": {
                                        "stop_reason": "tool_use"
                                        if action
                                        else "end_turn",
                                        "stop_sequence": None,
                                    },
                                    "usage": {"output_tokens": 1},
                                },
                            ),
                            ("message_stop", {"type": "message_stop"}),
                        ]
                    )
                elif model.client == "codex-cli":
                    response = {
                        "id": "resp_" + uuid.uuid4().hex,
                        "object": "response",
                        "created_at": int(time.time()),
                        "status": "in_progress",
                        "output": [],
                    }
                    events.append(
                        (
                            "response.created",
                            {"type": "response.created", "response": response},
                        )
                    )
                    if action and action[1] == "tool_search":
                        callid, _, args, _ = action
                        item = {
                            "id": "tsc_" + callid,
                            "type": "tool_search_call",
                            "call_id": callid,
                            "execution": "client",
                            "arguments": args,
                            "status": "completed",
                        }
                    elif action:
                        callid, name, args, namespace = action
                        item = {
                            "id": "fc_" + callid,
                            "type": "function_call",
                            "call_id": callid,
                            "name": name,
                            "arguments": json.dumps(args),
                            "status": "completed",
                            "namespace": namespace,
                        }
                        events.extend(
                            [
                                (
                                    "response.output_item.added",
                                    {
                                        "type": "response.output_item.added",
                                        "output_index": 0,
                                        "item": dict(
                                            item, arguments="", status="in_progress"
                                        ),
                                    },
                                ),
                                (
                                    "response.function_call_arguments.delta",
                                    {
                                        "type": "response.function_call_arguments.delta",
                                        "item_id": item["id"],
                                        "output_index": 0,
                                        "delta": item["arguments"],
                                    },
                                ),
                                (
                                    "response.function_call_arguments.done",
                                    {
                                        "type": "response.function_call_arguments.done",
                                        "item_id": item["id"],
                                        "output_index": 0,
                                        "arguments": item["arguments"],
                                    },
                                ),
                            ]
                        )
                    else:
                        item = {
                            "id": "msg_done",
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "Fixture complete.",
                                    "annotations": [],
                                }
                            ],
                            "status": "completed",
                        }
                    events.extend(
                        [
                            (
                                "response.output_item.done",
                                {
                                    "type": "response.output_item.done",
                                    "output_index": 0,
                                    "item": item,
                                },
                            ),
                            (
                                "response.completed",
                                {
                                    "type": "response.completed",
                                    "response": dict(
                                        response,
                                        status="completed",
                                        output=[item],
                                        usage={
                                            "input_tokens": 1,
                                            "output_tokens": 1,
                                            "total_tokens": 2,
                                        },
                                    ),
                                },
                            ),
                        ]
                    )
                else:
                    chunk = {
                        "id": "chatcmpl_" + uuid.uuid4().hex,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": "fixture",
                    }
                    delta = {"role": "assistant"}
                    if action:
                        callid, name, args, namespace = action
                        delta["tool_calls"] = [
                            {
                                "index": 0,
                                "id": callid,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": json.dumps(args),
                                },
                            }
                        ]
                    else:
                        delta["content"] = "Fixture complete."
                    events = [
                        (
                            None,
                            dict(
                                chunk,
                                choices=[
                                    {"index": 0, "delta": delta, "finish_reason": None}
                                ],
                            ),
                        ),
                        (
                            None,
                            dict(
                                chunk,
                                choices=[
                                    {
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "tool_calls"
                                        if action
                                        else "stop",
                                    }
                                ],
                                usage={
                                    "prompt_tokens": 1,
                                    "completion_tokens": 1,
                                    "total_tokens": 2,
                                },
                            ),
                        ),
                    ]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                for event, data in events:
                    if event:
                        self.wfile.write(("event: " + event + "\n").encode())
                    self.wfile.write(("data: " + json.dumps(data) + "\n\n").encode())
                if model.client == "opencode":
                    self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except Exception as e:
                model.failure = str(e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"fixture request failed")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main(client, pi_module=None):
    with Fixture() as f:
        executable = {"codex-cli": "codex", "claude-code": "claude"}.get(client, client)
        version = f.run([executable, "--version"]).stdout.strip()
        model = Model(f, client)
        with serve(model) as url:
            env = dict(f.env)
            if client == "pi":
                f.run([BINARY, "agent", "connect", client, "--json"])
                actions = f.base / "actions.json"
                actions.write_text(json.dumps(model.actions))
                env.update(
                    HASP_FIXTURE_URL=url, HASP_FIXTURE_APPROVAL_KEY=model.approval_key
                )
                args = [
                    "node",
                    str(pathlib.Path(__file__).with_name("pi.mjs")),
                    str(pi_module),
                    str(actions),
                ]
            elif client == "claude-code":
                f.run([BINARY, "agent", "connect", client, "--json"])
                env.update(
                    ANTHROPIC_BASE_URL=url,
                    ANTHROPIC_API_KEY="synthetic-local-fixture-key",
                    CLAUDE_CODE_MAX_OUTPUT_TOKENS="1024",
                    ENABLE_TOOL_SEARCH="false",
                )
                args = [
                    "claude",
                    "--bare",
                    "--setting-sources",
                    "",
                    "--settings",
                    "{}",
                    "--strict-mcp-config",
                    "--mcp-config",
                    str(f.base / "claude" / ".claude.json"),
                    "--no-session-persistence",
                    "--disable-slash-commands",
                    "--model",
                    "claude-sonnet-4-5",
                    "--tools",
                    "Bash",
                    "--allowedTools",
                    "Bash",
                    "mcp__hasp__*",
                    "--permission-mode",
                    "bypassPermissions",
                    "--print",
                    "--output-format",
                    "stream-json",
                    "--verbose",
                    "--system-prompt",
                    "Execute the deterministic local fixture tool requests.",
                    "Run the local HASP fixture.",
                ]
            elif client == "codex-cli":
                f.run([BINARY, "agent", "connect", client, "--json"])
                config = {
                    "model_provider": "fixture",
                    "model_providers.fixture": {
                        "name": "fixture",
                        "base_url": url + "/v1",
                        "wire_api": "responses",
                        "requires_openai_auth": False,
                        "supports_websockets": False,
                    },
                    "mcp_servers.hasp": {
                        "command": str(f.home / "bin" / "hasp-agent-codex-cli"),
                        "env_vars": [
                            "HASP_HOME",
                            "HASP_SOCKET",
                            "HASP_MASTER_PASSWORD",
                            "HASP_AGENT_SAFE_MODE",
                            "HASP_SESSION_TOKEN",
                            "HASP_AGENT_PROJECT_ROOT",
                            "HASP_AGENT_CONSUMER",
                            "HASP_TEST",
                            "HASP_TELEMETRY_DISABLED",
                        ],
                    },
                    "shell_environment_policy.inherit": "all",
                    "shell_environment_policy.ignore_default_excludes": True,
                    "features.unified_exec": True,
                    "features.shell_snapshot": False,
                    "analytics.enabled": False,
                    "model": "gpt-5.4",
                    "model_reasoning_effort": "low",
                }

                def toml(v):
                    if isinstance(v, dict):
                        return (
                            "{"
                            + ",".join(k + "=" + toml(value) for k, value in v.items())
                            + "}"
                        )
                    return json.dumps(v)

                args = [
                    "codex",
                    "exec",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "--json",
                    "--sandbox",
                    "danger-full-access",
                    "-C",
                    str(f.root),
                ]
                for k, v in config.items():
                    args.extend(["-c", k + "=" + toml(v)])
                args.append("Run the deterministic local HASP fixture.")
            else:
                config = {
                    "$schema": "https://opencode.ai/config.json",
                    "model": "fixture/test",
                    "small_model": "fixture/test",
                    "enabled_providers": ["fixture"],
                    "provider": {
                        "fixture": {
                            "npm": "@ai-sdk/openai-compatible",
                            "name": "fixture",
                            "options": {
                                "baseURL": url + "/v1",
                                "apiKey": "synthetic-local-fixture-key",
                            },
                            "models": {
                                "test": {
                                    "name": "test",
                                    "limit": {"context": 128000, "output": 4096},
                                }
                            },
                        }
                    },
                    "share": "disabled",
                    "autoupdate": False,
                    "permission": "allow",
                }
                (f.base / "opencode.json").write_text(json.dumps(config))
                f.run([BINARY, "agent", "connect", client, "--json"])
                args = [
                    "opencode",
                    "--pure",
                    "run",
                    "--format",
                    "json",
                    "--auto",
                    "--dir",
                    str(f.root),
                    "--model",
                    "fixture/test",
                    "Run the deterministic local HASP fixture.",
                ]
            result = f.run(f.launch(client, args), env=env, timeout=100, check=False)
            if result.returncode or model.failure:
                print(
                    json.dumps(
                        {
                            "client": client,
                            "exit": result.returncode,
                            "model_error": model.failure,
                            "sent": model.sent,
                            "fixture_config": (
                                f.base / "codex" / "config.toml"
                            ).read_text()
                            if client == "codex-cli"
                            else "",
                            "stderr": result.stderr.replace(VALUE, "<synthetic>")[
                                -2000:
                            ],
                            "stdout": result.stdout.replace(VALUE, "<synthetic>")[
                                -3000:
                            ],
                        }
                    )
                )
                raise AssertionError("client failed")
            if client == "pi":
                outputs = json.loads(result.stdout.strip().splitlines()[-1])
                for entry in outputs:
                    call_id = "call_" + str(len(model.sent))
                    model.sent.append((call_id, entry["name"]))
                    model.seen[call_id] = flatten(entry["output"])
                model.i = len(model.actions)
            print(
                json.dumps(
                    dict(model.verify(), version=version, operator_dialog="stubbed")
                )
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "client", choices=("codex-cli", "claude-code", "opencode", "pi")
    )
    parser.add_argument("--hasp-binary", type=pathlib.Path, required=True)
    parser.add_argument(
        "--pi-module", type=pathlib.Path, help="Installed Pi SDK dist/index.js"
    )
    options = parser.parse_args()
    BINARY = str(options.hasp_binary.resolve(strict=True))
    if not os.access(BINARY, os.X_OK):
        parser.error("--hasp-binary must be executable")
    if options.client == "pi" and options.pi_module is None:
        pi_cli = shutil.which("pi")
        if pi_cli:
            options.pi_module = pathlib.Path(pi_cli).resolve().parents[1] / "index.js"
        if options.pi_module is None or not options.pi_module.is_file():
            parser.error("Set --pi-module to the installed SDK's dist/index.js")
    main(options.client, options.pi_module)
