# 0009 — Audit log

## Context
Record security-relevant actions with the authenticated actor, queryable in the UI.

## User stories
- As an admin, I review who did what and when, with filters.

## Functional requirements
- FR-1: Append-only audit events: `who` (authenticated user), `action`, `target`,
  `details`, `timestamp`.
- FR-2: Emit events for: login/logout, user changes, settings changes, provisioner
  create/select/delete, issue, sign, revoke, renew, ACME provisioner/EAB changes.
- FR-3: Query with filters: action, user, time range; newest first; paginated.

## Data model
- `audit_events(id, who, action, target, details, created_at)`

## Routes / UI
- `GET /audit`

## Acceptance criteria
- Given I perform an auditable action, When I open the audit log, Then I see an
  entry with the correct actor, action, and timestamp.
- Given filters (action/user/time), When I apply them, Then only matching entries
  are shown.

## Tests
- event emission per action; query/filter logic; actor is the session user
  (not "system").

## Out of scope
- External SIEM export (future).
