# 0010. ACME enablement in the UI

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
Step-CA supports ACME, but the predecessor UI only showed ACME directory URLs
read-only. Operators need to manage ACME provisioners and External Account Binding
(EAB) credentials, and onboard clients.

## Decision Drivers
- First-class ACME support for automated certificate issuance.
- Manage EAB keys when `requireEAB` is enabled.

## Considered Options
- Full ACME management (provisioners + EAB + directory/client hints)
- Read-only directory display (status quo)
- Defer ACME entirely

## Decision Outcome
Chosen option: "Full ACME management" via the admin API: create/edit/delete ACME
provisioners (challenge types, requireEAB), generate/list/revoke EAB keys, and show
directory URL + client snippets (certbot/acme.sh/Caddy/Traefik).

### Consequences
- Good, because covers the main homelab automation use case.
- Bad, because more admin-API surface and tests.
- Neutral, depends on ADR-0004 (SDK/admin API) and remote management enabled.

## More Information
See spec 0010-acme.md. Admin endpoints incl. `/admin/acme/eab/{provisioner}`.
