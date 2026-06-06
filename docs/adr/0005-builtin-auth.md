# 0005. Built-in local authentication with roles and first-run setup

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The predecessor had **no authentication** while controlling a CA. We want auth from
day one without mandating an external IdP for a homelab.

## Decision Drivers
- Security by default; the UI grants full control over the PKI.
- Minimal env config; set up via the UI.

## Considered Options
- Local users (username/password, roles, sessions) + first-run super-admin
- OIDC/SSO only
- Reverse-proxy/forward-auth only

## Decision Outcome
Chosen option: "Local users + first-run super-admin". OIDC and forward-auth are
documented as future, optional additions.

### Consequences
- Good, because secure out of the box, no external dependency.
- Bad, because we own password storage (use argon2id) and session/CSRF handling.
- Neutral, roles: superadmin / admin / viewer.

## More Information
See spec 0003. Sessions via `scs`; CSRF protection for all mutating forms.
