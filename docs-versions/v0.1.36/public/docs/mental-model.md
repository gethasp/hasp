# Mental model

HASP gives you a way to stop handing secrets to tools as plain text. Think in six objects:

- a vault stores named secrets on your machine
- a project binding says which repo can use which names
- a target says which workflow receives which subset
- a consumer is an app or agent that wants access
- a grant allows one scoped delivery
- the broker does the delivery and writes the audit trail

That is the product. The rest of the CLI exists to create, inspect, and repair those objects.

Use the [Glossary](glossary.md) when you need the exact vocabulary.

## The short version

You put secrets into the vault. You bind a repo. A committed value-free manifest
can describe requirements and targets. You connect the app or agent that works
inside that repo. HASP gives the app or agent a reference, then resolves that
reference at execution time.

The app gets the value. The agent should get metadata, handles, or brokered tools. The repo gets guardrails. The audit log records the action.

This is the shape to keep in your head:

<figure class="docs-figure">
  <div class="model-diagram" role="img" aria-label="A HASP request starts at a vault item, passes through project binding and grant, and is delivered by the broker to an app, agent, or command.">
    <div class="model-label">mental model</div>
    <div class="model-flow">
      <div class="model-card">
        <b>Vault</b>
        <span>Stores the named item on this machine.</span>
      </div>
      <div class="model-arrow" aria-hidden="true">→</div>
      <div class="model-card">
        <b>Project</b>
        <span>Checks the repo boundary and visible reference.</span>
      </div>
      <div class="model-arrow" aria-hidden="true">→</div>
      <div class="model-card">
        <b>Grant</b>
        <span>Matches actor, action, scope, and time.</span>
      </div>
      <div class="model-arrow" aria-hidden="true">→</div>
      <div class="model-card dark">
        <b>Broker</b>
        <span>Delivers to the app, agent, or command and writes audit.</span>
      </div>
    </div>
  </div>
  <figcaption><strong>Read the checks in order.</strong> The value starts in the vault. The project binding says whether this repo can name it. The grant says whether this request can receive it. The broker delivers only after those checks pass.</figcaption>
</figure>

You can use HASP for normal local commands too. The agent-safe path matters because coding agents read their own prompts, logs, command output, and sometimes the files they just wrote. A value that appears in any of those places can become part of the agent context. HASP tries to keep the value out of that context.

## The vault

The vault is the local encrypted store under `HASP_HOME`. It holds named items such as `OPENAI_API_KEY`, `DATABASE_URL`, or a JSON service account.

The vault answers one question: do I have this secret on this machine?

<figure class="docs-figure">
  <div class="model-diagram" role="img" aria-label="The vault stores a secret, while project bindings, sessions, and grants decide whether a consumer can use it.">
    <div class="policy-split">
      <div class="policy-panel">
        <b>Vault answers</b>
        <div class="question">Do I have this secret here?</div>
        <span>It stores named items under <code>HASP_HOME</code>. It does not choose the repo, actor, action, or time window.</span>
      </div>
      <div class="policy-panel">
        <b>Policy answers</b>
        <div class="policy-grid" aria-label="Policy checks">
          <div class="policy-chip">Which repo?</div>
          <div class="policy-chip">Which ref?</div>
          <div class="policy-chip">Which actor?</div>
          <div class="policy-chip">How long?</div>
        </div>
      </div>
    </div>
  </div>
  <figcaption>Opening the vault proves possession. Bindings, sessions, and grants decide use.</figcaption>
</figure>

The vault does not answer:

- which repo may use it
- which agent may ask for it
- whether this command should receive it right now
- whether plaintext display is allowed

Those decisions live in bindings, sessions, and grants.

Use `hasp init` when you want the vault and nothing else. Use `hasp setup` when you want the guided path that can create the vault, bind a repo, import values, and connect a consumer.

## Vault items and references

A vault item is the stored secret. A reference is the name or alias a command can ask for.

Those two things are related, but they are not the same. `OPENAI_API_KEY` might be the item in the vault. A repo can expose it as `secret_01` or `STRIPE_TEST_KEY`. The alias lets you give a project a stable handle without teaching every tool the real vault name.

That distinction matters in docs, logs, and agent prompts. The handle can appear in those places. The value should not.

Use `hasp secret list` to see managed items and visible references. Use `hasp secret show` or `hasp secret get` to inspect metadata. Use `hasp secret reveal` or `hasp secret copy` when you need plaintext and you are outside a protected agent flow, or after you issue a short plaintext grant.

## The project binding

A project binding is a repo boundary. It tells HASP that commands running inside a project can request a named set of secrets.

The binding answers two questions:

- which repo is asking
- which vault items that repo can name

HASP treats project roots as explicit boundaries. That keeps a value you imported for one repo from leaking into another repo because both happen to run on the same machine.

Use `hasp project bind` when you want a direct binding. Use `hasp bootstrap` when you want a repo binding plus an agent profile. Use `hasp project adopt` when you want HASP to scan a workspace and bind many git repos with the same defaults.

## Targets

A target is a named workflow inside a project, such as `server.dev`,
`build.config`, or `release.sign`.

Targets live in `.hasp.manifest.json` and are value-free. They say which refs a
workflow needs and how those refs should be delivered. They do not approve
access, store values, or make the whole project secret set available.

Use `hasp project requirements` and `hasp project targets` to inspect the repo
contract. Use `hasp run --target <name>`, `hasp inject --target <name>`, or
`hasp write-env --target <name>` when you want HASP to expand one declared
subset through the normal broker path.

## Consumers

A consumer is anything that asks HASP for a secret.

HASP has two consumer families:

- apps, which you run through `hasp app`
- agents, which you connect through `hasp agent` or `hasp mcp`

Apps tend to expect environment variables or files. Agents need more care. They can inspect output, write files, run shell commands, and call tools. HASP gives agents a brokered surface so they can request a managed value without reading the raw value.

Use `hasp app connect` for a local app profile. Use `hasp agent connect` for a coding agent profile. Use `hasp mcp` or `hasp agent mcp <profile>` when an agent speaks MCP over stdio.

## Grants

A grant is permission to resolve a reference. It is valid only when the actor, project, action, and time scope all match.

<figure class="docs-figure">
  <div class="model-diagram" role="img" aria-label="A grant checks actor, project, action, and time scope before HASP delivers a secret.">
    <div class="model-label">grant scope</div>
    <div class="grant-grid">
      <div class="grant-panel">
        <b>Actor</b>
        <span>Which app, agent, command, or MCP client is asking?</span>
      </div>
      <div class="grant-panel">
        <b>Project</b>
        <span>Which repo root is this request attached to?</span>
      </div>
      <div class="grant-panel">
        <b>Action</b>
        <span>Resolve, reveal, copy, run, inject, or write?</span>
      </div>
      <div class="grant-panel">
        <b>Time</b>
        <span>Once, the current session, or a short window?</span>
      </div>
    </div>
    <div class="grant-core">
      <b>All four must match.</b>
      <span>A value existing in the vault is not enough for delivery.</span>
    </div>
  </div>
  <figcaption>A grant stays small: one actor, one project, one action, one short scope.</figcaption>
</figure>

Grants prevent the vault from becoming a global local dictionary. A command should not get a value because the value exists. It should get the value because the current project, consumer, and action match a scoped grant.

HASP uses short scopes:

- `once` for one delivery
- `session` for the current broker session
- `window` for a short time window

Use `once` for one-off commands. Use `session` when a tool needs a few related requests. Use `window` when a local workflow would become noisy with repeated prompts, and keep the window short.

## Sessions

A session is the broker-side context for a consumer. It lets HASP answer questions such as:

- which host or agent is asking
- which project root the request belongs to
- whether the request is still alive
- whether plaintext display has a temporary exception

Most users should not need to manage sessions by hand. `hasp run`, `hasp inject`, `hasp app`, and `hasp agent` open and use sessions for their flows.

Use `hasp session open` when you need to debug a brokered flow. Use `hasp session resolve` to inspect a token. Use `hasp session revoke` when you want to shut down one token or all active sessions. Use `hasp session grant-plaintext` when an operator has to allow a protected reveal or copy action for a short window.

## Brokered execution

Brokered execution means HASP resolves values at the last moment and gives them to the child process, not to the repo and not to the agent transcript.

`hasp run` resolves environment references:

```bash
hasp run --project-root . \
  --env OPENAI_API_KEY=secret_01 \
  --grant-project window \
  --grant-secret session \
  -- sh -c 'test -n "$OPENAI_API_KEY"'
```

`hasp inject` resolves environment values and file references:

```bash
hasp inject --project-root . \
  --file GOOGLE_APPLICATION_CREDENTIALS=@gcp_service_account \
  -- node scripts/sync.js
```

`hasp write-env` writes a repo-visible env file on purpose. Treat it as a convenience tool, not the default safe path.

## The MCP path

MCP changes the trust boundary. A shell command receives environment variables. An MCP client receives tools.

When an agent connects to `hasp mcp`, the agent can call HASP tools instead of reading a raw `.env` file. The value stays behind the broker. The agent gets the result it needs, or a refusal that explains which grant, project, or reference is missing.

Use MCP when the agent can work through tools. Use `hasp run` when you need to run a normal command. Use `hasp inject` when the command needs a temp credential file.

## Audit

The audit log gives you local evidence. It records setup, bindings, grants, secret operations, app and agent connections, brokered deliveries, and failures.

The audit log does not make a secret safe after it leaks. It gives you the trail you need to see what happened and what to rotate.

Use `hasp audit` for a full local log. Use `hasp audit tail` when you want recent events during setup or debugging. Use `hasp audit --incident-bundle` when you need a redacted package for review.

## Redaction

Redaction is a backup guard, not the main design.

The safer design is to keep secrets out of output. Redaction helps when a managed value shows up anyway. HASP can rewrite known managed values in output paths it controls, and `hasp check-repo` can scan a repo for managed values that landed in files.

Use `hasp check-repo` before commits, releases, or support bundles. Use git hooks from `hasp project bind` or `hasp setup` when you want the check to run before a commit.

## Where a secret should live

Use this order when you choose a delivery path:

<figure class="docs-figure">
  <div class="model-diagram" role="img" aria-label="HASP delivery choices ordered from brokered delivery to plaintext manual use.">
    <div class="model-label">delivery path</div>
    <div class="delivery-diagram">
      <div class="delivery-row">
        <b>Vault + broker</b>
        <span>The value stays behind HASP until delivery.</span>
      </div>
      <div class="delivery-row">
        <b>hasp run</b>
        <span>A child process receives environment values.</span>
      </div>
      <div class="delivery-row">
        <b>hasp inject</b>
        <span>A command receives environment values or temp files.</span>
      </div>
      <div class="delivery-row">
        <b>hasp write-env</b>
        <span>A repo-visible env file is written on purpose.</span>
      </div>
      <div class="delivery-row">
        <b>reveal or copy</b>
        <span>Plaintext leaves the broker for manual use.</span>
      </div>
    </div>
  </div>
  <figcaption>Prefer the first path that lets the work finish. Move down the list only when the tool requires more exposure.</figcaption>
</figure>

1. Keep the value in the vault and let the broker resolve it.
2. Pass the value to a child process environment with `hasp run`.
3. Materialize a temp file with `hasp inject` when a tool requires a file path.
4. Write a repo env file with `hasp write-env` after a human accepts that exposure.
5. Reveal or copy plaintext for manual work, then rotate if you pasted it into an unsafe place.

The first three paths keep the repo cleaner. The last two paths trade safety for convenience.

## Common mistakes

### Treating the vault as the policy

The vault stores values. Project bindings and grants decide use.

If a command fails because a value is not visible in a repo, add or inspect the binding. Do not copy the value into `.env` as a workaround.

### Binding the wrong directory

Bind the repo root you want to protect. A nested package, a generated folder, or a parent workspace can give you the wrong boundary.

Use `hasp project status --project-root .` to see what HASP thinks the project root is.

### Giving agents plaintext

Agents can quote, summarize, write, and log. A plaintext secret in the agent context is hard to reason about after the fact.

Use references and brokered tools. If you must reveal a value while an agent is active, use `hasp session grant-plaintext` and keep the grant short.

### Writing convenience files before you mean to

`hasp write-env` exists because some tools require `.env`. Use it after you decide that a repo-visible file is acceptable.

If the workflow can run through `hasp run` or `hasp inject`, use those first.

## How to choose the first command

Use `hasp setup` for a guided first run.

Use `hasp secret add` when the vault exists and you want to add one value.

Use `hasp import` when the value already lives in `.env`, JSON, or pasted shell-export text.

Use `hasp project bind` when the repo boundary is missing.

Use `hasp agent connect` when a coding agent needs a profile.

Use `hasp proof` when you want to confirm that the current repo can receive one brokered value.

Use `hasp doctor` when you expected a flow to work and it did not.

## Reading error messages

Most HASP errors point at one missing object:

- vault errors mean HASP cannot open the encrypted store
- binding errors mean the repo has no visible reference
- daemon errors mean the local broker is not reachable
- permission errors mean a grant, session, or plaintext exception is missing
- repo check errors mean a managed value appeared in a file

Fix the missing object. Avoid working around the boundary with copied plaintext.

For exact terms, use the [Glossary](glossary.md).
