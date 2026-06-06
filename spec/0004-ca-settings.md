# 0004 — Step-CA connection (configured in the UI)

## Context

The CA connection is configured in the UI and stored (encrypted where sensitive),
not via env (ADR-0004/0006).

## User stories

- As an admin, I enter my CA URL + root fingerprint and verify connectivity.
- As an admin, I can store admin credentials for remote management.

## Functional requirements

- FR-1: Persist CA settings: `ca_url`, `root_fingerprint`, optional admin identity
  (`admin_provisioner`, `admin_subject`) and `admin_secret` (sealed via 0002).
- FR-2: A **Test connection** action fetches the CA roots and verifies the
  fingerprint; report success/failure clearly.
- FR-3: TLS to the CA is verified against the pinned root; no skip-verify.
- FR-4: Validation: `ca_url` is http(s); fingerprint is 40–64 hex chars.
- FR-5: Secrets are never returned to the client (write-only fields; show "set").

## Data model

- `ca_settings(id, ca_url, root_fingerprint, admin_provisioner, admin_subject,
admin_secret_sealed, created_at, updated_at)` (single row).
- Note (ADR-0012): the `admin_secret` here is a password and cannot sign Step-CA
  admin tokens. Spec/0005 extends `ca_settings` with an admin certificate chain
  and a sealed admin private key for x5c admin-token signing.

## Routes / UI

- `GET /settings`, `POST /settings`, `POST /settings/test`

## Acceptance criteria

- Given valid CA URL + fingerprint, When I Test, Then I see success and roots load.
- Given a wrong fingerprint, When I Test, Then it fails with a clear message.
- Given I save an admin secret, When I reload, Then the field shows "set" and the
  value is not sent to the browser.
- Given an invalid CA URL, When I save, Then validation rejects it.

## Tests

- settings CRUD; sealing of admin secret; fingerprint validation; test-connection
  against a mock CA (roots endpoint).

## Out of scope

- Provisioner/ACME management (0005/0010).
