# Value classification

An item stored for runtime injection may be confidential or ordinary
configuration. HASP treats every existing and new item as confidential until
the local operator explicitly classifies it.

| Classification | Repository scans | Brokered output |
| --- | --- | --- |
| `confidential` | Matches the value and its supported encodings | Redacts matching values and encodings |
| `configuration` | Omits this item's value from managed-value matching | Leaves this item's value readable |

The existing detection limits still apply to confidential items, including the
six-byte minimum value length and the default 4 MiB scan limit per source.
An identical value stored in another confidential item still matches when that
item is included in the scan or redaction pass. Scans consider all confidential
vault items, including items not exposed to the current project.
Scan statistics report the number of configuration items excluded by this
explicit policy.

## Classify a reviewed value

An account or project ID is not automatically public. Decide whether the
particular value can appear in code, links, and command output before changing
its classification:

```bash
hasp secret classify PROJECT_ID --classification configuration
hasp secret show PROJECT_ID
```

Run classification commands from a local operator process outside a
connected-agent repository. Protected agent processes cannot classify items,
even with a one-time plaintext grant. MCP has no classification mutation tool.
The command records the item name and old/new classifications in audit, without
the value.

Restore confidential handling with:

```bash
hasp secret classify PROJECT_ID --classification confidential
```

`secret show`, JSON inventory/search results, and visible MCP references report
the effective classification. Missing or unknown stored classifications count
as confidential. HASP does not infer this choice from a name, provider, numeric
shape, project exposure, or a failed hook.

## Delivery still requires authorization

Configuration items still live in the encrypted vault. Using a named reference
still requires exposure to the selected project, a project lease, and any
secret grant required by its access policy. File injection still uses temporary
files and cleanup. `secret reveal` and `secret copy` retain their explicit
plaintext authorization rules in protected contexts.

For an exposed configuration item, a brokered command may deliberately emit a
useful link containing its value. For a confidential item, the same command's
captured output is redacted:

```bash
hasp run --project-root . --grant-project session --env ID=@PROJECT_ID -- \
  sh -c 'printf "https://example.com/project/%s\n" "$ID"'
```

Classification is read when an operation loads its items. It does not rewrite
past output or alter a command that is already running.

## Value writes reset the choice

Every upsert, including add-with-replacement, import, update, rotation, capture,
and MCP writes, resets the affected item to confidential. This also applies
when the submitted bytes are unchanged. Review and classify it again if it
should remain ordinary configuration. An item name reused for a credential
must not retain an earlier decision about an identifier.
