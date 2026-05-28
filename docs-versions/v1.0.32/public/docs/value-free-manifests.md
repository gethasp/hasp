# Value-free manifests

HASP can read one committed repo contract:

```text
.hasp.manifest.json
```

The file lives at the project root. You commit it so a teammate, CI job, app
profile, or coding agent can see what the repo expects.

The file does not store secrets. It stores names, refs, target names, delivery
names, paths, and placeholder example locations. That distinction matters. A
manifest can help the repo explain itself without turning git into a secret
store.

<p class="docs-principle"><em>A committed value-free manifest can describe requirements and targets.</em></p>

## The short version

A value-free manifest answers two questions:

- Which refs does this repo expect?
- Which atomic refs belong to the same credential set?
- Which target gets which subset?

It does not answer these questions:

- Does this machine have the value?
- Is this repo bound to that value?
- May this command receive the value right now?
- May an agent read the plaintext?

The vault, project binding, grant, and broker answer those questions later.
Treat the manifest as repo input. It describes a request. It is not authority.

## The sentence, word by word

"A committed value-free manifest can describe requirements and targets" has a
specific meaning in HASP:

- committed: the file is normal repo metadata. It can live in git, go through
  review, and travel with the project.
- value-free: the file contains no plaintext secret values and no local grant
  decisions. It can name things, but it cannot contain the things themselves.
- manifest: the file is a machine-readable contract, not a README convention.
  HASP parses it, validates it, and uses it to drive commands.
- requirements: the repo declares the refs it expects, their kind, whether they
  are required, and how reviewers should classify them.
- credential sets: the repo can name coupled roles, such as a Google OAuth
  `client_id` and `client_secret`, while keeping each value as its own ref.
- targets: the repo declares named workflows, and each workflow receives only
  the refs and delivery names listed for that target.

The sentence does not mean a checkout can use the values by having the file. It
means the checkout can explain what it needs. The machine still needs matching
vault items. The repo still needs a binding. The run still needs grants. The
broker still decides whether and how to deliver.

## Why commit the file

Without a manifest, a new developer learns required secrets from failures,
old README text, `.env.example`, app code, or another person. That works until
the repo grows.

A repo may have local development, integration tests, and release scripts. They
may share one underlying vault item but need different delivery names:

```text
API_BASE_URL
  server.dev          -> API_BASE_URL
  server.integration  -> HASP_TEST_API_BASE_URL
  release.sign        -> API_BASE_URL
```

The manifest lets the repo say that in one place. The value stays in the local
vault. The manifest says what shape each workflow expects.

## What value-free means

Value-free means no plaintext credential material and no local approval state.

Do not put these in `.hasp.manifest.json`:

- API keys, passwords, tokens, certificates, private keys, cookies, session IDs,
  or connection strings
- fields named `value`, `values`, `grant`, `grants`, `convenience_grants`,
  `tokens`, `session_token`, or `workspace_trust`
- local hook state
- local session state
- local vault file paths
- user-specific absolute paths
- workspace trust decisions
- shell snippets that compute secrets

HASP rejects the local authority field names above, even when they appear deep
inside the JSON tree.

Value-free does not mean metadata-free. A target named `release.sign` or an
item name such as `STRIPE_LIVE_SECRET_KEY` can reveal how the repo works. Use
neutral aliases when provider names or environments would leak too much.

## The file HASP reads

HASP V1 reads JSON. The filename is fixed:

```text
.hasp.manifest.json
```

The file sits at the bound project root, not in each package. Use one project
binding for one repo boundary. Use targets inside the manifest for app,
platform, test, and deploy workflows inside that repo.

Use a second project binding only when you need a separate trust boundary, such
as a sibling repo or a sub-root that must not share refs.

## Complete example

This manifest describes three targets:

- `server.dev` receives the env vars used by local server work.
- `server.integration` receives a narrower set for integration tests.
- `release.sign` receives a file credential path for release packaging.

No value appears in the file.

```json
{
  "version": "v1",
  "project": {
    "name": "example-product",
    "description": "Local development and build requirements."
  },
  "references": [
    { "alias": "secret_01", "item": "OPENAI_API_KEY" },
    { "alias": "secret_02", "item": "DATABASE_URL" },
    { "alias": "file_01", "item": "RELEASE_SIGNING_KEY" },
    { "alias": "config_01", "item": "API_BASE_URL" }
  ],
  "requirements": [
    {
      "ref": "secret_01",
      "kind": "kv",
      "required": true,
      "classification": "secret",
      "description": "Server-side API token for local broker development."
    },
    {
      "ref": "secret_02",
      "kind": "kv",
      "required": true,
      "classification": "secret",
      "description": "Database connection string for local integration tests."
    },
    {
      "ref": "file_01",
      "kind": "file",
      "required": true,
      "classification": "secret",
      "description": "Release signing key material used by packaging scripts."
    },
    {
      "ref": "config_01",
      "kind": "kv",
      "required": true,
      "classification": "public_config",
      "description": "API origin used by local server checks."
    }
  ],
  "targets": [
    {
      "name": "server.dev",
      "description": "Local server development.",
      "root": "apps/server",
      "command": ["make", "-C", "apps/server", "test-integration"],
      "delivery": [
        { "as": "env", "name": "OPENAI_API_KEY", "ref": "secret_01" },
        { "as": "env", "name": "DATABASE_URL", "ref": "secret_02" },
        { "as": "env", "name": "API_BASE_URL", "ref": "config_01" }
      ],
      "examples": [
        { "format": "env", "path": "apps/server/.env.example" }
      ]
    },
    {
      "name": "server.integration",
      "description": "Integration test run.",
      "root": "apps/server",
      "command": ["make", "-C", "apps/server", "test-integration"],
      "delivery": [
        { "as": "env", "name": "DATABASE_URL", "ref": "secret_02" },
        { "as": "env", "name": "HASP_TEST_API_BASE_URL", "ref": "config_01" }
      ]
    },
    {
      "name": "release.sign",
      "description": "Release packaging script.",
      "root": ".",
      "delivery": [
        { "as": "file", "name": "HASP_RELEASE_SIGNING_KEY_FILE", "ref": "file_01" }
      ]
    }
  ]
}
```

## Field by field

### `version`

Use `"v1"` when the manifest declares requirements, targets, project metadata,
or target examples. HASP rejects other versions.

### `project`

`project.name` and `project.description` are optional human labels. Keep them
plain. Do not put tenant names, customer names, incident names, or private host
names in these fields unless the repo already exposes that metadata.

### `references`

`references` maps repo-facing aliases to vault item names.

```json
{ "alias": "secret_01", "item": "OPENAI_API_KEY" }
```

The alias is what repo workflows can request. The item is the name of the local
vault item. The manifest can use a neutral alias such as `secret_01`, then
operators can keep provider-specific names in their local vault.

Requirements and delivery entries can refer to an alias:

```json
{ "ref": "secret_01" }
```

They can also refer to a named ref:

```json
{ "ref": "@OPENAI_API_KEY" }
```

The named-ref form still requires a matching `references` entry. HASP does not
let a target invent a new ref by writing `@SOMETHING` in delivery.

### `requirements`

A requirement says one ref should exist for this repo.

```json
{
  "ref": "secret_01",
  "kind": "kv",
  "required": true,
  "classification": "secret",
  "description": "Server-side API token for local broker development."
}
```

`ref` must match a declared reference. `kind` is `kv` or `file`. `classification`
is `secret` or `public_config`.

### `credential_sets`

`credential_sets` groups related requirement refs by role without storing a
combined secret value.

```json
{
  "name": "google.oauth.web",
  "kind": "google_oauth_client",
  "members": {
    "client_id": "config_01",
    "client_secret": "secret_01",
    "redirect_uri": "config_02"
  }
}
```

The `google_oauth_client` kind requires:

- `client_id`: `kv`, `public_config`
- `client_secret`: `kv`, `secret`
- `redirect_uri`: optional `kv`, `public_config`

The `generic` kind accepts any lowercase role names that point at existing
requirements. Use `generic` only when HASP has no built-in schema for the
credential shape.

Targets deliver individual roles from a set:

```json
{
  "as": "env",
  "name": "GOOGLE_CLIENT_SECRET",
  "from_set": "google.oauth.web",
  "role": "client_secret"
}
```

`from_set` plus `role` is mutually exclusive with `ref`. A delivery entry must
use either a direct `ref` or a set role, never both.

Use `secret` for values that must stay out of files, logs, prompts, and client
bundles. Use `public_config` only for values you would be willing to ship to a
client app or publish in an example file. The label does not make a value safe.
It tells HASP which placeholder to generate and gives reviewers a warning.

### `targets`

A target is a named workflow inside the repo. Examples:

```text
server.dev
server.integration
release.sign
test.integration
```

Target names must start with a lowercase letter or digit. They can contain
lowercase letters, digits, dots, underscores, and hyphens. They cannot contain
slashes, backslashes, control characters, or more than 64 characters.

HASP treats target names case-insensitively for duplicate checks. `server.dev`
and `Server.Dev` conflict.

### `target.root`

`root` is the working directory for that target, relative to the project root.
Use `"."` or omit the field for the project root.

HASP resolves symlinks when it validates paths. A target root, generated output,
or example path cannot escape the project root.

### `target.command`

`command` is an argv array:

```json
"command": ["make", "-C", "apps/server", "test-integration"]
```

Do not use shell strings such as `"pnpm dev"`. HASP rejects empty command
arguments and control characters. It also does not run this command when it
loads, inspects, or validates the manifest.

`hasp run --target server.dev` can use the command. If a target has no command,
you can pass one after `--`.

### `target.delivery`

Delivery entries map a ref to a destination name for one target.

```json
{ "as": "env", "name": "DATABASE_URL", "ref": "secret_02" }
```

`as` can be:

- `env`
- `file`
- `xcconfig`

`name` must look like an environment variable: it starts with a letter or
underscore and then uses letters, digits, or underscores.

HASP rejects dangerous destination names because they can alter process
behavior instead of configuring your app:

- `PATH`
- `LD_PRELOAD`
- `NODE_OPTIONS`
- `PYTHONPATH`
- `RUBYOPT`
- `SSH_AUTH_SOCK`
- `HOME`
- `SHELL`
- names starting with `DYLD_`
- names starting with `GIT_`
- names starting with `HASP_`

File requirements can only be delivered with `"as": "file"`. HASP rejects a
file item delivered as an env var or xcconfig value.

### `target.delivery.output`

`output` is allowed only for `xcconfig` delivery:

```json
{
  "as": "xcconfig",
  "name": "API_BASE_URL",
  "ref": "config_01",
  "output": "build/Secrets.generated.xcconfig"
}
```

This declares where `hasp write-env --target build.config` should write a
generated file. It does not write the file during inspection. It also does not
make file materialization the preferred path. Use runtime delivery when the tool
can accept env vars or broker-owned temp files.

### `target.examples`

Examples describe placeholder files that HASP can check or generate:

```json
{ "format": "env", "path": "apps/server/.env.example" }
```

Supported formats are `env` and `xcconfig`.

Generated examples use placeholders:

- `__HASP_SECRET__` for secret key-value requirements
- `__HASP_PUBLIC_CONFIG__` for public config requirements
- `__HASP_FILE__` for file requirements

HASP writes a marker into generated examples. It refuses to overwrite a
hand-authored file silently.

### `default_capture_policy`

The manifest may include `default_capture_policy`. Local binding state wins if
the project already has a local default. Use this field only as a repo-level
default for new capture flows. Do not use it for grants.

## What HASP does with the manifest

### Inspect requirements

```bash
hasp project requirements --project-root .
hasp project requirements --project-root . --target server.dev --json
```

HASP reads requirements, checks whether refs are present and exposed, and may
suggest `hasp secret add` commands. It does not print values. It does not run
target commands.

### Inspect targets

```bash
hasp project targets --project-root .
hasp project targets --project-root . --json
```

Target inspection lists names, refs, delivery kinds, examples, and whether a
command exists. Agent-facing MCP target listing is narrower: it omits target
command argv and secret values.

### Check the project

```bash
hasp project doctor --project-root .
hasp project doctor --project-root . --json
```

Project doctor reports manifest diagnostics with codes and booleans. It avoids
raw command output, command argv, socket paths, and secret values.

It can report problems such as:

- unavailable target commands
- stale examples
- generated outputs that are not ignored
- workspace-visible secret delivery
- requirement kind mismatches
- target drift

### Generate examples

```bash
hasp project examples --project-root . --target server.dev --check
hasp project examples --project-root . --target server.dev --write
```

`--check` compares the expected placeholder file with the file on disk.
`--write` creates or updates generated examples. HASP never resolves real vault
values into examples.

### Run a target

```bash
hasp run --project-root . --target server.dev --grant-project window --grant-secret session
```

HASP expands only the delivery entries declared by `server.dev`. It then uses the
normal broker path. The project binding, grant, redaction, and audit checks
still apply.

When you use `--target`, `hasp run` rejects extra `--env` or `--file` mappings.
The manifest target owns the delivery set for that run.

If a target has no command, pass one after `--`:

```bash
hasp run --project-root . --target test.integration -- go test ./...
```

### Inject a target into another command

```bash
hasp inject --project-root . --target release.sign -- ./scripts/package-release.sh
```

Use this when the manifest should provide env or file refs, but you want to
choose the command at runtime.

### Write a generated value file

```bash
hasp write-env --project-root . --target build.config --grant-convenience window
```

This writes plaintext into a workspace-visible generated file. Use it when a
tool needs a real file. Prefer `run` or `inject` when they work.

### Seed an app profile

```bash
hasp app connect server-dev --project-root . --target server.dev
hasp app run server-dev
```

`app connect --target` copies the target command and delivery mapping into a
local app profile. The app profile is local state. If someone changes the
manifest later, HASP does not rewrite the saved profile behind your back.

## Drift review

HASP records a local review for target expansion outside git. It hashes the
target command, refs, delivery, and outputs.

If the committed manifest later changes those pieces, human CLI flows warn
before continuing. `hasp project doctor --json` reports `target_drift`.

This catches changes such as:

- `server.dev` starts asking for a new ref
- a target command changes
- a generated output path changes
- a delivery name changes from `DATABASE_URL` to another destination

The review record lives in local HASP state. It is not committed.

## Rules HASP enforces

HASP validates manifests before it uses them:

- `version` must be `v1` when extended fields appear.
- Requirement refs must be unique.
- Requirement refs must be declared in `references`.
- Requirement kind must be `kv` or `file`.
- Requirement classification must be `secret` or `public_config`.
- Target names must match HASP's safe target-name pattern.
- Target names cannot conflict by case.
- Target roots, generated outputs, and example paths must stay inside the repo.
- Target commands must be argv arrays with non-empty safe arguments.
- Delivery format must be `env`, `file`, or `xcconfig`.
- Delivery destination names must be variable-shaped and not dangerous.
- Delivery names cannot repeat inside one target.
- Delivery refs must point at known requirements.
- File requirements can only use file delivery.
- `output` is allowed only for `xcconfig`.
- Example format must be `env` or `xcconfig`.
- Secret or local authority fields are rejected anywhere in the JSON tree.

These checks do not prove the command is safe. They keep the manifest inside the
contract HASP can reason about.

## Metadata rules

Use the same care you use for `.env.example`, README setup notes, and CI
configuration.

Safe enough for most repos:

- neutral aliases such as `secret_01`, `file_01`, `config_01`
- target names such as `server.dev`, `server.integration`, `test.integration`
- destination names the app already uses, such as `DATABASE_URL`
- generated example paths inside the repo

Review before committing:

- provider names
- production environment names
- customer names
- tenant IDs
- private hostnames
- incident names
- deploy topology in descriptions

Do not rely on the manifest to hide metadata from someone who can read the
repo. The manifest hides values, not the fact that a workflow exists.

## Common mistakes

### Putting the real value in `item`

Wrong:

```json
{ "alias": "secret_01", "item": "sk-live-real-value" }
```

Right:

```json
{ "alias": "secret_01", "item": "OPENAI_API_KEY" }
```

`item` is the vault item name. It is not the value.

### Treating a target as authorization

A target narrows the delivery set. It does not approve access.

This command still needs grants:

```bash
hasp run --project-root . --target server.dev --grant-project window --grant-secret session
```

### Delivering a file item as env text

Wrong:

```json
{ "as": "env", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "file_01" }
```

Right:

```json
{ "as": "file", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "file_01" }
```

File delivery gives the command a path to a broker-owned temp file.

### Using dangerous env names

Do not use a manifest to set `PATH`, `LD_PRELOAD`, `NODE_OPTIONS`, `DYLD_*`,
`GIT_*`, or `HASP_*`. HASP rejects these names because they can change the
runtime or the broker itself.

### Expecting generated examples to contain values

Generated examples contain placeholders only. They exist for framework
compatibility and onboarding. They are not a secret delivery path.

## Minimal manifest

Start small:

```json
{
  "version": "v1",
  "references": [
    { "alias": "secret_01", "item": "OPENAI_API_KEY" }
  ],
  "requirements": [
    {
      "ref": "secret_01",
      "kind": "kv",
      "required": true,
      "classification": "secret"
    }
  ],
  "targets": [
    {
      "name": "server.dev",
      "root": "apps/server",
      "command": ["make", "-C", "apps/server", "test-integration"],
      "delivery": [
        { "as": "env", "name": "OPENAI_API_KEY", "ref": "secret_01" }
      ],
      "examples": [
        { "format": "env", "path": "apps/server/.env.example" }
      ]
    }
  ]
}
```

Then run:

```bash
hasp project requirements --project-root .
hasp project targets --project-root .
hasp project examples --project-root . --target server.dev --check
```

When those read cleanly, connect an app or run the target through the broker:

```bash
hasp app connect server-dev --project-root . --target server.dev
hasp app run server-dev
```

or:

```bash
hasp run --project-root . --target server.dev --grant-project window --grant-secret session
```
