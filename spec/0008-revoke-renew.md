# 0008 — Revoke & renew

## Context
The predecessor only marked revocation locally and never told the CA. Here,
revocation is **real** (against the CA), and renew is configurable.

## User stories
- As an admin, I revoke a certificate and it is actually revoked at the CA.
- As a user, I renew a certificate with a chosen validity.

## Functional requirements
- FR-1: Revoke via the CA (by serial) with a reason; on success mark local status
  `revoked` and record an audit event. Surface CA errors.
- FR-2: Renew: re-issue for the same CN/SANs with a chosen validity (bounded by the
  provisioner max; default configurable, not hard-coded), update stored material.
- FR-3: Guard rails: cannot revoke an already-revoked cert; confirmation required.

## Routes / UI
- `POST /certificates/{id}/revoke`, `POST /certificates/{id}/renew`

## Acceptance criteria
- Given an active certificate, When I revoke it, Then the CA receives a revoke
  request and the local status becomes `revoked` only on CA success.
- Given the CA rejects the revoke, When I revoke, Then the local status is unchanged
  and the error is shown.
- Given an active certificate, When I renew with 30 days, Then a new cert with the
  same CN/SANs and ~30-day validity is stored.

## Tests
- revoke success/failure against a mock CA (status only changes on success);
  renew validity bounds; audit events.

## Out of scope
- Automated/scheduled renewal.
