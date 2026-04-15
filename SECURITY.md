# Security policy

If you found a security problem in HASP, do not open a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository.

Include:

- what you found
- which versions or commits are affected
- how to reproduce it
- any workaround you know about

If canonical source reporting is not available in the repo settings, contact the
maintainers through GitHub first and avoid posting exploit details in public.

## What to expect

We will try to:

- confirm the report
- assess impact
- work on a fix
- publish a coordinated advisory when the fix is ready

## Supported release line

Security fixes should be assumed for:

- the current `main` branch
- the latest tagged release

Older tags may not receive separate backports.

## Scope

Please report issues such as:

- auth bypass
- privilege escalation
- unsafe approval bypass
- secret leakage
- remote code execution
- data exposure
- unsafe defaults in public install or upgrade paths
