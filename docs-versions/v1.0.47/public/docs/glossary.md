# Glossary

HASP uses a small vocabulary. These terms show up in help output, docs, audit events, and errors.

## Vault

The encrypted local store under `HASP_HOME`.

The vault stores named items on the machine. It proves that the secret exists locally. It does not decide which repo, app, agent, or command may receive the value.

## Item

One named secret in the vault.

An item can be a token, password, connection string, or file-shaped credential such as a JSON service account.

## Reference

A name or alias a repo can request.

The reference can be safer to show than the raw vault item name. A repo can ask for `secret_01` while the vault item keeps its provider-specific name.

## Project

The repo root HASP uses as a boundary.

Commands running inside that boundary can use the references exposed to that project. Another repo does not inherit those references just because it runs on the same machine.

## Binding

The record that connects a project to visible references.

If a brokered command cannot see a secret, inspect the binding before copying plaintext into the repo.

## Target

A named workflow inside a project.

Targets are declared in `.hasp.manifest.json`. A target can describe the refs,
delivery names, root, command argv, and placeholder examples for one workflow.
It is repo metadata, not authorization. See
[Value-free manifests](value-free-manifests.md) for the manifest contract.

## Consumer

An app, agent, command, or MCP client that asks HASP for access.

Apps usually need environment variables or files. Agents should prefer references and brokered tools so the raw value stays out of prompts, logs, and generated files.

## Grant

Scoped permission to deliver a value.

A grant matches actor, project, action, and time scope. The vault holding a value is not enough for delivery.

## Session

Broker context for a running consumer.

Sessions let HASP track which host, process, repo, and temporary plaintext exceptions belong to a request.

## MCP

The tool protocol agents use to talk to HASP without reading raw values.

Use MCP when an agent can work through brokered tools. Use `hasp run` or `hasp inject` when a normal command needs environment variables or files.

## Audit log

Local evidence for operations and access, written as a chain.

Audit helps you understand what happened. It does not make a leaked secret safe after the fact.

## Plaintext grant

A short exception that allows a protected reveal or copy action.

Use it for manual work only. Keep the scope short and rotate the upstream value if it lands in an unsafe place.
