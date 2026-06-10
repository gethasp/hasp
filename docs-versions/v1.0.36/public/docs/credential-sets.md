# Credential sets

Status: shipped in HASP v1.0.32.

HASP models coupled credentials as typed credential sets, not as one opaque
stored secret.

The motivating example is a Google OAuth web client. A working app usually
needs a `client_id`, a `client_secret`, and at least one redirect URI. Those
values are coupled because they describe one provider-side client, but they do
not all have the same sensitivity, delivery shape, or rotation behavior.

The vault should keep the values atomic. The credential set should describe how
those atomic values fit together.

## Manifest shape

Use normal `references` and `requirements` for each atomic value, then declare
the relationship in `credential_sets`:

```json
{
  "version": "v1",
  "references": [
    { "alias": "config_01", "item": "GOOGLE_CLIENT_ID" },
    { "alias": "secret_01", "item": "GOOGLE_CLIENT_SECRET" },
    { "alias": "config_02", "item": "GOOGLE_REDIRECT_URI" }
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
    },
    {
      "ref": "config_02",
      "kind": "kv",
      "required": false,
      "classification": "public_config"
    }
  ],
  "credential_sets": [
    {
      "name": "google.oauth.web",
      "kind": "google_oauth_client",
      "members": {
        "client_id": "config_01",
        "client_secret": "secret_01",
        "redirect_uri": "config_02"
      }
    }
  ],
  "targets": [
    {
      "name": "server.dev",
      "delivery": [
        {
          "as": "env",
          "name": "GOOGLE_CLIENT_ID",
          "from_set": "google.oauth.web",
          "role": "client_id"
        },
        {
          "as": "env",
          "name": "GOOGLE_CLIENT_SECRET",
          "from_set": "google.oauth.web",
          "role": "client_secret"
        }
      ]
    }
  ]
}
```

Each member remains a normal HASP item:

- `GOOGLE_CLIENT_ID`: key-value item, often public config
- `GOOGLE_CLIENT_SECRET`: key-value item, secret
- `GOOGLE_REDIRECT_URI`: key-value item, public config

Targets should deliver roles from the set, not blindly deliver the whole set:

```json
{
  "as": "env",
  "name": "GOOGLE_CLIENT_SECRET",
  "from_set": "google.oauth.web",
  "role": "client_secret"
}
```

`hasp project targets`, `hasp project requirements --target`,
`hasp project examples`, `hasp project doctor`, `hasp run --target`,
`hasp inject --target`, and MCP target tools resolve set-backed delivery to the
member refs before authorization. Agents see refs, roles, and set names, not
plaintext values.

## Shipped set kinds

`google_oauth_client` is schema-checked:

- `client_id` is required and must be a `kv` requirement classified as
  `public_config`.
- `client_secret` is required and must be a `kv` requirement classified as
  `secret`.
- `redirect_uri` is optional and must be a `kv` requirement classified as
  `public_config` when present.

`generic` accepts any lowercase role names that point at existing requirements.
Use it when HASP has no built-in schema yet, while keeping each member's
classification and kind on the requirement.

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

## Semantics

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

Target review includes the resolved member refs through the target signature.
Changing a set member mapping changes the target's resolved refs and requires
renewed local review before brokered execution can authorize the target.

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

Credential sets feed delivery recipes:

- env pair for frameworks that read `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET`
- generated `.env` example with placeholders only
- workspace-visible generated files only through explicit target review and
  workspace-output commands

Delivery recipes must be deny-by-default. A target that asks for `client_id`
does not receive `client_secret` unless it maps that role explicitly.

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
