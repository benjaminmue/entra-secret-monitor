# Entra Secret Monitor

Watches Entra ID app registrations for client secrets and certificates about to expire,
and reports them. Runs in three modes; the portal exposes a REST interface under
`/api/v1`.

## Stack
Python 3.12. The service in `app/` is standard library only, on purpose. The portal in
`portal/` may use the pinned dependencies in `requirements-portal.txt`.

## What a review needs to know
- `app/` must not gain a third-party import. The security gate proves that claim by
  running the suite once without any extras installed; an import there breaks it.
- Upper bounds in `requirements-portal.txt` must never sit below a version carrying a
  security fix. The cap on `cryptography` was `<46` while every published fix needed 46
  or newer, which quietly made the project unpatchable.
- Entra credentials and the secrets this tool reports on must not appear in logs, error
  responses or the audit trail.
- `main` is protected by a ruleset without bypass. Everything lands through a pull
  request with a green gate.

## Conventions
Code, comments and commit messages in English. Public repository.
