# Agent mental model

An agent treats HASP as the route for brokered work.

Teach the agent one habit: ask for the work to happen, not for the value. The agent names a repo, a safe reference, and a command. HASP checks the project, grant, session, and target. The child process gets the secret if the request passes. The agent gets the command result and the audit trail keeps the record.

Use the [Mental model](mental-model.md) for the operator view. This page shows the same flow from the agent side.

## The agent sees handles

An agent working through HASP sees a smaller world than a shell with `.env` loaded. That smaller world is the point.

<figure class="docs-figure">
  <div class="agent-surface-diagram" role="img" aria-label="The agent sees prompt instructions, safe references, HASP tools, and command output. The secret value stays behind the broker.">
    <div class="model-label">agent surface</div>
    <div class="agent-surface-grid">
      <div class="agent-surface-card">
        <b>Prompt</b>
        <span>Use <code>@OPENAI_API_KEY</code> through HASP. Do not paste the value.</span>
      </div>
      <div class="agent-surface-card">
        <b>Tool list</b>
        <span><code>hasp_list</code>, <code>hasp_run</code>, <code>hasp_inject</code>, <code>hasp_redact</code></span>
      </div>
      <div class="agent-surface-card">
        <b>Broker</b>
        <span>Checks repo, session, grant, and reference.</span>
      </div>
      <div class="agent-surface-card dark">
        <b>Output</b>
        <span>Status, stdout, stderr, and a local audit event.</span>
      </div>
    </div>
    <div class="agent-secret-vault">
      <b>Secret value</b>
      <span>Stored in the vault. Delivered to the child process only.</span>
    </div>
  </div>
  <figcaption><strong>The handle can appear in the transcript.</strong> Keep the value out of prompts, logs, and files the agent can read.</figcaption>
</figure>

The agent can reason with these objects:

- named refs such as `@OPENAI_API_KEY`
- neutral aliases such as `secret_01`
- manifest targets such as `server.integration`
- tool results from `hasp_list`, `hasp_targets`, or `hasp_target_explain`
- command output from `hasp_run` or `hasp_inject`

The agent asks for plaintext only when the brokered route cannot run the task.

## One run from the agent's seat

Imagine a repo with a test command that needs `OPENAI_API_KEY`.

<figure class="docs-figure">
  <div class="agent-timeline" role="img" aria-label="Timeline from user prompt through agent tool calls, broker checks, child process execution, and audit.">
    <div class="model-label">timeline with prompt and tool annotations</div>
    <div class="agent-time-row">
      <div class="agent-time-mark">1</div>
      <div class="agent-time-body">
        <b>User prompt</b>
        <code>Run the integration tests. Use HASP for OPENAI_API_KEY.</code>
        <span>The user gives the agent a handle and a boundary.</span>
      </div>
    </div>
    <div class="agent-time-row">
      <div class="agent-time-mark">2</div>
      <div class="agent-time-body">
        <b>Agent lists refs</b>
        <code>hasp_list {"project_root":"."}</code>
        <span>The agent confirms which refs this repo can name.</span>
      </div>
    </div>
    <div class="agent-time-row">
      <div class="agent-time-mark">3</div>
      <div class="agent-time-body">
        <b>Agent asks for work</b>
        <code>hasp_run {"env":{"OPENAI_API_KEY":"@OPENAI_API_KEY"},"command":["pnpm","test:integration"]}</code>
        <span>The tool call names a command and a ref. It leaves plaintext behind HASP.</span>
      </div>
    </div>
    <div class="agent-time-row">
      <div class="agent-time-mark">4</div>
      <div class="agent-time-body">
        <b>HASP checks policy</b>
        <code>repo + session + grant + ref</code>
        <span>The broker rejects the request if any check fails.</span>
      </div>
    </div>
    <div class="agent-time-row">
      <div class="agent-time-mark">5</div>
      <div class="agent-time-body">
        <b>Child process runs</b>
        <code>OPENAI_API_KEY=... pnpm test:integration</code>
        <span>The process gets the environment value. The agent sees only output.</span>
      </div>
    </div>
    <div class="agent-time-row">
      <div class="agent-time-mark">6</div>
      <div class="agent-time-body">
        <b>Agent reports result</b>
        <code>exit=0, tests passed, audit event written</code>
        <span>The agent can summarize the run without learning the key.</span>
      </div>
    </div>
  </div>
  <figcaption><strong>The agent's best request is a brokered action.</strong> The value moves only between HASP and the child process.</figcaption>
</figure>

The transcript can now show the whole decision trail:

```text
User: Run the integration tests. Use HASP for OPENAI_API_KEY.
Agent: I will call hasp_list, then run the test command with @OPENAI_API_KEY.
Tool: hasp_list -> refs: @OPENAI_API_KEY, target: server.integration
Tool: hasp_run -> exit 0
Agent: The integration tests passed.
```

No one had to paste the key into the chat.

## The prompt shape

Good prompts give the agent a task, a repo boundary, and a delivery rule.

```text
Run the integration tests in this repo.
Use HASP for @OPENAI_API_KEY.
Use hasp_run or the server.integration target.
Do not reveal, print, or write the secret value.
If HASP refuses access, tell me which ref or grant is missing.
```

That prompt gives the agent enough room to work. It also tells the agent how to fail.

Use this shorter version when the repo already has targets:

```text
Run the server.integration target through HASP and report the test result.
Keep managed values out of the transcript.
```

## Where MCP fits

MCP is the tool lane agents already understand. HASP occupies that lane as the
broker between tool calls and vault values.

<figure class="docs-figure">
  <div class="agent-mcp-map" role="img" aria-label="The agent reaches HASP through a stdio MCP process. HASP checks the session and project, then sends values only to child commands.">
    <div class="model-label">mcp broker path</div>
    <div class="agent-mcp-row">
      <div class="agent-mcp-node">
        <b>Agent</b>
        <span>Calls MCP tools by name.</span>
      </div>
      <div class="agent-mcp-arrow">JSON-RPC</div>
      <div class="agent-mcp-node">
        <b>HASP MCP</b>
        <span><code>hasp mcp</code> or <code>hasp agent mcp &lt;id&gt;</code></span>
      </div>
      <div class="agent-mcp-arrow">policy</div>
      <div class="agent-mcp-node dark">
        <b>Broker</b>
        <span>Checks repo, session, grant, target, and ref.</span>
      </div>
    </div>
    <div class="agent-mcp-result">
      <b>Child process receives the value.</b>
      <span>The agent receives stdout, stderr, exit code, redaction flags, and audit-backed metadata.</span>
    </div>
  </div>
  <figcaption>MCP is the transport. HASP still owns the secret boundary.</figcaption>
</figure>

There are two commands to know:

- `hasp mcp` starts the generic stdio MCP server.
- `hasp agent mcp <agent-id>` starts the same tool surface with profile-aware session setup.

Use the profile-aware command for first-class agents such as Codex CLI, Claude
Code, Cursor, Aider, Pi, Hermes, and OpenClaw. It opens or reuses a daemon-backed
session, labels the caller as `agent:<id>`, sets the project root when the
profile has one, and enables agent-safe mode for protected workflows.

Generic MCP config looks like this:

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["mcp"]
    }
  }
}
```

Profile-aware config uses the agent command:

```json
{
  "mcpServers": {
    "hasp": {
      "command": "hasp",
      "args": ["agent", "mcp", "codex-cli"]
    }
  }
}
```

If the agent launches helpers that also call HASP, start the agent through
`hasp agent launch <id> -- <command>` or `hasp agent shell <id>`. The launcher
pushes `HASP_SESSION_TOKEN` and safe-mode metadata into the whole child process
tree, including helpers outside the MCP server process.

## MCP handshake

A strict MCP client starts with `initialize`, then asks for tools, then calls
one tool at a time.

<figure class="docs-figure">
  <div class="agent-mcp-sequence" role="img" aria-label="MCP sequence from initialize to tools list to tool call.">
    <div class="model-label">stdio mcp sequence</div>
    <div class="agent-mcp-step">
      <b>1. initialize</b>
      <code>{"method":"initialize","params":{"protocolVersion":"2025-06-18"}}</code>
      <span>HASP returns a negotiated protocol version, tool capability, and server name.</span>
    </div>
    <div class="agent-mcp-step">
      <b>2. tools/list</b>
      <code>{"method":"tools/list"}</code>
      <span>The agent sees tool names, descriptions, and JSON input schemas.</span>
    </div>
    <div class="agent-mcp-step">
      <b>3. tools/call</b>
      <code>{"method":"tools/call","params":{"name":"hasp_run","arguments":{...}}}</code>
      <span>HASP runs the brokered action or returns a JSON-RPC error.</span>
    </div>
  </div>
  <figcaption>HASP ignores MCP notifications without an id. That keeps clients from seeing extra replies on the stdio stream.</figcaption>
</figure>

Test the generic server without opening an agent:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp
```

Test a profile-aware server the same way:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp agent mcp codex-cli
```

For a full handshake:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"docs-check","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | hasp mcp
```

The default response lists these tools:

| Tool | Agent use |
| --- | --- |
| `hasp_list` | List project-scoped refs and safe named refs. |
| `hasp_check` | Scan the project for managed values that leaked into files. |
| `hasp_targets` | List sanitized manifest targets, delivery kinds, refs, and prerequisite status. |
| `hasp_target_explain` | Explain one target without command argv or values. |
| `hasp_run` | Run a command with secret refs mapped into environment variables. |
| `hasp_inject` | Run a command with secret refs mapped to broker-owned credential files. |
| `hasp_secret_get` | Confirm metadata and get a safe named ref. It returns no raw value. |
| `hasp_redact` | Redact managed values from text before quoting logs. |

## MCP arguments that matter

Most HASP MCP tools accept the same broker fields:

- `project_root` binds the request to a repo. If omitted, HASP uses `HASP_AGENT_PROJECT_ROOT` or `.`.
- `session_token` lets a wrapper pass an existing daemon-backed session. If omitted, profile-aware MCP opens one.
- `host_label` names the caller in audit events. Profile-aware MCP uses `agent:<id>`.
- `grant_project` can be `once`, `session`, or `window`.
- `grant_secret` can be `once`, `session`, or `window`.

Use `window` for project approval when an agent will run several related tools
inside one repo. Use `session` for secret access when the same run will call a
test, retry, and inspect logs. Use `once` when the command has a narrow,
single-shot shape.

## MCP tool calls

A basic brokered run uses three calls.

First, it asks what the repo can name:

```json
{
  "name": "hasp_list",
  "arguments": {
    "project_root": ".",
    "grant_project": "window"
  }
}
```

Then it runs the command with an environment ref:

```json
{
  "name": "hasp_run",
  "arguments": {
    "project_root": ".",
    "grant_project": "window",
    "grant_secret": "session",
    "env": {
      "OPENAI_API_KEY": "@OPENAI_API_KEY"
    },
    "command": ["pnpm", "test:integration"]
  }
}
```

If the tool needs a credential file, the agent uses `hasp_inject`:

```json
{
  "name": "hasp_inject",
  "arguments": {
    "project_root": ".",
    "grant_project": "window",
    "grant_secret": "session",
    "files": {
      "GOOGLE_APPLICATION_CREDENTIALS": "@GCP_SERVICE_ACCOUNT"
    },
    "command": ["node", "scripts/sync.js"]
  }
}
```

Those calls keep the agent focused on the job. The agent names a ref and a command. HASP owns resolution.

## Tool results

`hasp_run` and `hasp_inject` return the command result:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "stdout_truncated": false,
  "stderr_truncated": false,
  "stdout_bytes_omitted": 0,
  "stderr_bytes_omitted": 0,
  "redacted": true,
  "suppressed": false
}
```

HASP streams command output through the redactor before the agent sees it. It
also caps each stream, so a noisy process stops at a bounded response size. If the
agent sees `redacted: true`, it can report that HASP removed a managed value
from the output. If it sees `stdout_truncated` or `stderr_truncated`, it reports
the visible output and the omitted byte count.

Manifest target calls add target metadata:

```json
{
  "target": "server.integration",
  "manifest_hash": "..."
}
```

Targets keep the agent from inventing secret mappings. `hasp_targets` and
`hasp_target_explain` return sanitized descriptions, refs, delivery kinds,
destination names, prerequisite status, and the manifest identity. They leave
out raw values and repo-controlled command argv.

MCP execution refuses two target shapes:

- a target combined with extra `env` or `files` mappings
- a target that writes workspace-visible secret files, such as generated
  xcconfig output

Each refusal points the agent back to a human CLI flow for workspace-visible
artifacts.

## Trusted harness tools

The default MCP catalog avoids tools that accept raw values or mutate vault
state. A trusted local harness can opt in with:

```bash
HASP_MCP_ENABLE_UNSAFE_SECRET_WRITE_TOOLS=1 hasp mcp
```

That adds:

- `hasp_capture`
- `hasp_secret_add`
- `hasp_secret_update`
- `hasp_secret_delete`
- `hasp_secret_expose`
- `hasp_secret_hide`

Keep those tools out of normal agent configs. They exist for local setup,
controlled evals, and migration harnesses. Day-to-day agents use `hasp_run`,
`hasp_inject`, `hasp_secret_get`, and `hasp_redact`.

## Choose the path

<figure class="docs-figure">
  <div class="agent-choice-diagram" role="img" aria-label="Agent decision chart for choosing hasp tools.">
    <div class="model-label">agent decision chart</div>
    <div class="agent-choice-row">
      <b>Need to discover refs?</b>
      <span>Call <code>hasp_list</code> or <code>hasp_targets</code>.</span>
    </div>
    <div class="agent-choice-row">
      <b>Need an env var?</b>
      <span>Call <code>hasp_run</code> with <code>env</code> mappings.</span>
    </div>
    <div class="agent-choice-row">
      <b>Need a credential file?</b>
      <span>Call <code>hasp_inject</code> with <code>files</code> mappings.</span>
    </div>
    <div class="agent-choice-row">
      <b>Need to clean output?</b>
      <span>Call <code>hasp_redact</code> before quoting logs.</span>
    </div>
    <div class="agent-choice-row blocked">
      <b>Need plaintext?</b>
      <span>Stop and ask for an operator decision. Protected flows block reveal and copy until the operator grants a short exception.</span>
    </div>
  </div>
  <figcaption>Pick the first tool that can finish the work. Plaintext is an operator action, not an agent shortcut.</figcaption>
</figure>

For repo-defined workflows, prefer manifest targets. Targets let the repo name the expected refs once, and the agent can call a stable target instead of rebuilding the mapping by memory.

```json
{
  "name": "hasp_run",
  "arguments": {
    "project_root": ".",
    "target": "server.integration",
    "grant_project": "window",
    "grant_secret": "session",
    "command": ["pnpm", "test:integration"]
  }
}
```

If the agent only knows a secret name, it can ask for metadata first:

```json
{
  "name": "hasp_secret_get",
  "arguments": {
    "project_root": ".",
    "name": "OPENAI_API_KEY"
  }
}
```

The result can include `named_reference: "@OPENAI_API_KEY"` and
`available_in_project: true`. It still omits the raw value.

## Blocked run reports

A failure report names the missing piece.

```text
HASP refused the run because this repo cannot name @OPENAI_API_KEY.
I did not receive the secret value.
Please bind that ref to this project or give me a different target.
```

For an expired session:

```text
HASP refused the run because the session grant expired.
I can retry through hasp_run if you approve a new session grant.
```

For a tool that expects a file:

```text
This command wants a credential file path.
I can rerun it with hasp_inject using @GCP_SERVICE_ACCOUNT.
```

The agent reports the broker decision and stops there. Copying a key into `.env` changes the security story and leaves cleanup work behind.

MCP errors use JSON-RPC error responses. Read the message field:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32000,
    "message": "target cannot be combined with explicit env or files mappings"
  }
}
```

Translate that into a developer-facing report:

```text
HASP refused the MCP tool call because the target already defines its delivery.
I did not run the command.
I can retry with the target alone or with explicit env mappings, but not both.
```

## Transcript rules for agents

Use these rules in agent instructions, project docs, or a system prompt:

```text
Use HASP refs for managed secrets.
Prefer hasp agent mcp <profile> over plain hasp mcp when a profile exists.
Call hasp_list before guessing a ref.
Call hasp_targets before using a repo-defined workflow.
Use hasp_run for environment variables.
Use hasp_inject for credential files.
Use hasp_secret_get for metadata, not plaintext.
Quote command output only after redaction if it may contain a managed value.
Ask for raw secret values only after a human approves plaintext access.
```

These rules give the agent a narrow protocol. They also give the developer a readable transcript: the agent asked for a ref, HASP checked policy, the command ran, and the agent reported the result.

## Review an agent run

After the run, check three places:

1. The transcript contains refs, commands, and output. Secret values stay out.
2. The audit log shows the session, grant, reference, and delivery path.
3. The repo stays clean. Run `hasp check-repo` if the agent wrote files.

If all three pass, the agent used HASP the way a developer expects: enough access to finish the task, no raw value in the agent context.
