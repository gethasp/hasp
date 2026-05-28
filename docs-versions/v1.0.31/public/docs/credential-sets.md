# Credential sets

Status: scoped design. Credential sets are not a shipped manifest field in
HASP v1.0.31.

HASP should model coupled credentials as typed credential sets, not as one
opaque stored secret.

The motivating example is a Google OAuth web client. A working app usually
needs a `client_id`, a `client_secret`, and at least one redirect URI. Those
values are coupled because they describe one provider-side client, but they do
not all have the same sensitivity, delivery shape, or rotation behavior.

The vault should keep the values atomic. The credential set should describe how
those atomic values fit together.

## Decision

Use a typed recipe over normal vault items:

```json
{
  "credential_sets": [
    {
      "name": "google.oauth.web",
      "kind": "google_oauth_client",
      "members": {
        "client_id": "@GOOGLE_CLIENT_ID",
        "client_secret": "@GOOGLE_CLIENT_SECRET",
        "redirect_uri": "@GOOGLE_REDIRECT_URI"
      }
    }
  ]
}
```

The shape above is illustrative, not accepted by current HASP releases.

Each member remains a normal HASP item:

- `GOOGLE_CLIENT_ID`: key-value item, often public config
- `GOOGLE_CLIENT_SECRET`: key-value item, secret
- `GOOGLE_REDIRECT_URI`: key-value item, public config

Targets should deliver roles from the set, not blindly deliver the whole set:

```json
{
  "as": "env",
  "from_set": "google.oauth.web",
  "map": {
    "GOOGLE_CLIENT_ID": "client_id",
    "GOOGLE_CLIENT_SECRET": "client_secret"
  }
}
```

The delivery recipe can also assemble a provider-shaped temporary file during a
brokered run. That assembled file is an execution artifact, not the canonical
stored value.

## Why not store a group as one secret

An opaque JSON secret is convenient, but it is the wrong default for HASP.

It loses field-level classification. In OAuth, `client_id` identifies the
client, while `client_secret` authenticates it. Treating both as the same
secret forces the stricter policy onto harmless config or accidentally weakens
the secret.

It breaks independent rotation. Google client secret rotation can add a new
secret, migrate traffic, and disable the old secret while the client ID stays
stable. A blob makes that lifecycle harder to represent and audit.

It widens grants. A caller that only needs `client_id` should not receive
`client_secret` because the two happened to be stored together.

It weakens redaction and audit. HASP should be able to report that a target used
the `client_secret` role without exposing the value or confusing it with the
`client_id` role.

## External constraints

Google's OAuth web-server documentation treats the downloaded
`client_secret.json` as client credentials, tells operators to store it
securely, and says to keep it outside the source tree when code is shared:
<https://developers.google.com/identity/protocols/oauth2/web-server>.

Google's OAuth setup guidance also describes client-secret rotation as a
specific lifecycle where a new secret is added, the app is migrated, and the old
secret is disabled: <https://support.google.com/googleapi/answer/6158849>.

RFC 6749 defines `client_id`, `client_secret`, and `redirect_uri` as distinct
OAuth parameters, and also notes that distributed clients can have components
with different security contexts: <https://datatracker.ietf.org/doc/html/rfc6749>.

AWS Secrets Manager supports JSON key-value secrets for coupled credential
shapes, especially where rotation functions expect specific fields:
<https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_json_structure.html>.
That validates the usefulness of structured credentials, but HASP should avoid
copying the blob-as-authority model because HASP's local broker can preserve
field-level authorization.

Kubernetes Secrets also allow multiple data keys in one Secret object:
<https://kubernetes.io/docs/concepts/configuration/secret/>. That validates the
operational need for multi-key credentials, but Kubernetes' namespace and
pod-access model is not HASP's grant model.

## Required semantics

A credential set must be value-free in repo metadata. It can name member refs,
roles, kinds, classification, and delivery recipes. It must never store member
values in `.hasp.manifest.json`.

Each member must retain its own:

- kind, such as `kv` or `file`
- classification, such as `secret` or `public_config`
- vault item name
- named reference
- rotation state
- audit identity

Set review must include:

- set name
- set kind and schema version
- member role-to-ref mapping
- member classifications
- target delivery mapping
- output paths for workspace-visible materialization

A grant to use a set must be scoped to a target/action. It must not imply
plaintext reveal for every member.

## Doctor behavior

`hasp project doctor` should validate a set as a unit while reporting member
failures separately.

Good diagnostics:

- missing `client_secret`
- `client_id` is present but not exposed to this project
- `client_secret` is classified as `public_config`, but the
  `google_oauth_client` schema requires `secret`
- target maps `client_secret` to a workspace-visible output without convenience
  approval
- target review is stale because the set member mapping changed

Bad diagnostics:

- "group invalid"
- "item not found"
- "Google auth failed"

## Delivery behavior

Credential sets should feed delivery recipes:

- env pair for frameworks that read `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`
- broker-owned temp JSON file for libraries that require a client secrets file
- generated `.env` example with placeholders only
- workspace-visible generated file only through explicit convenience approval

Delivery recipes must be deny-by-default. A target that asks for `client_id`
does not receive `client_secret` unless it maps that role explicitly.

## Open design work

Before implementation, define:

- manifest schema field names and versioning
- built-in schemas for `google_oauth_client`, database credentials, and service
  account JSON
- whether custom set kinds are allowed in v1 or only built-in kinds
- review signature changes
- MCP listing and explain output for set-backed targets
- migration path from today's explicit `requirements` and `targets`

## Rejected options

Do not add a generic `group` item kind. It obscures sensitivity and makes the
vault value shape do too much.

Do not introduce tag-based delivery for this. Tags are organization metadata,
not an execution contract.

Do not let repo manifests define arbitrary assembly scripts. Assembly must be a
HASP-owned recipe so values do not pass through shell expansion or agent-visible
text.

Do not treat every member of a set as secret. Some members are config, and
over-classifying them creates unnecessary friction. Under-classifying is worse,
so each built-in schema must declare the minimum safe classification per role.

## Interim v1 pattern

Until credential sets ship, model coupled credentials with separate manifest
requirements and explicit target delivery:

```json
{
  "version": "v1",
  "references": [
    { "alias": "config_01", "item": "GOOGLE_CLIENT_ID" },
    { "alias": "secret_01", "item": "GOOGLE_CLIENT_SECRET" }
  ],
  "requirements": [
    {
      "ref": "config_01",
      "kind": "kv",
      "required": true,
      "classification": "public_config"
    },
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
      "delivery": [
        { "as": "env", "name": "GOOGLE_CLIENT_ID", "ref": "config_01" },
        { "as": "env", "name": "GOOGLE_CLIENT_SECRET", "ref": "secret_01" }
      ]
    }
  ]
}
```

This keeps the committed repo contract value-free and preserves the main HASP
invariant: values are brokered at execution time, not stored in source control
or returned to agent context by default.
