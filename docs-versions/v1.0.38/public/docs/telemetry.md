# Telemetry

HASP CLI telemetry is disabled by default. The CLI never sends telemetry unless
you explicitly opt in during `hasp setup` or by running `hasp telemetry enable`.

The hard runtime override is:

```bash
export HASP_TELEMETRY_DISABLED=1
```

When this variable is set, telemetry cannot be enabled and no telemetry network
request is made even if prior consent was saved.

## Destination

Opted-in CLI telemetry goes only to HASP's first-party endpoint:

```text
https://telemetry.gethasp.com/v1/cli/ping
```

The CLI does not send telemetry directly to PostHog, Umami, Segment, or any
other third-party analytics endpoint.

## Commands

```bash
hasp telemetry status
hasp telemetry enable
hasp telemetry disable
hasp telemetry forget
hasp telemetry preview --json
```

- `status` shows consent state, environment override, endpoint, schema version,
  last ping time, and a short install-hash prefix.
- `enable` shows the policy summary and asks for confirmation unless `--yes` is
  provided.
- `disable` withdraws consent and stops collection and sending.
- `forget` deletes local telemetry state and requests erasure for retained
  install hashes when the endpoint is configured.
- `preview` prints the exact payload builder output without sending it.

These commands do not require the daemon, vault unlock, or a broker session.

## Setup Consent

Interactive `hasp setup` asks whether to allow optional CLI telemetry. The
default answer is no.

Non-interactive setup uses an explicit flag:

```bash
hasp setup --non-interactive --telemetry=never
hasp setup --non-interactive --telemetry=always
hasp setup --non-interactive --telemetry=off
hasp setup --non-interactive --telemetry=on
```

`--yes` never implies telemetry consent.

## Payload Contract

Telemetry uses one daily aggregate payload with schema version `1`.

Allowed fields:

- `schema_version`
- `install_id_hash`
- `hasp_version`
- `os`
- `arch`
- `install_method`
- `period_hours`
- `commands_24h`
- `commands_total`
- `top_root_commands`
- `setup`
- `features`
- `safety`
- `errors`
- `performance`

Allowed counters are fixed to public command or feature names. Unknown fields
are rejected by the client encoder and by the first-party ingest service.

## Data HASP Never Sends

HASP telemetry must never include:

- secret values
- secret names
- aliases
- refs
- vault IDs
- session tokens
- project paths
- repo names
- file names
- environment variable names
- command arguments or full command lines
- hostnames
- usernames or local user IDs
- raw error strings
- stack traces
- stdout or stderr
- audit log entries

The local audit log remains local. Telemetry is not an audit-log export path.

## Local State

Telemetry consent and counters are stored outside the encrypted vault so that
`hasp telemetry disable` and `hasp telemetry forget` work while the vault is
locked. The state file is written under the user's config directory with `0600`
permissions where the platform supports POSIX modes.

The local install identity is random and rotates yearly. HASP sends only a
derived hash. Prior hashes are retained locally long enough for `forget` to
request erasure for rows that may still be inside the server retention window.

## Retention And Erasure

The source of record is a first-party Cloudflare Worker backed by Cloudflare D1.
Live rows are keyed by install hash and day so they can be deleted when
`hasp telemetry forget` sends an erasure request.

The erasure ledger stores only install hash, timestamp, source, status, and
deleted-row count. It is retained only for accountability.

D1 Time Travel and backups can retain deleted rows until the configured backup
window expires. Restore runbooks must not reintroduce erased rows without
replaying the erasure ledger.

## Downstream Analytics

The default analytics path is D1-only. If HASP later mirrors aggregate telemetry
to another analytics tool, the mirror must run server-side after validation and
redaction. The CLI network contract remains first-party only.

Downstream mirrors must not use session replay, autocapture, surveys, feature
flags, user profiles, or raw install identity.

## Contributor Rules

New telemetry fields require all of the following in the same change:

- this document updated
- allowlist/schema update in the client and ingest service
- tests proving the field cannot carry forbidden data
- privacy review notes
- release-note disclosure

If any of those pieces are missing, the field must not ship.
