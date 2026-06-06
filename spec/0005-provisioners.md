# 0005 — Provisioner management

## Context

List provisioners, choose the active one for issuance, and create/delete via the
Step-CA admin API using SDK-signed admin tokens (ADR-0004).

## User stories

- As an admin, I see the CA's provisioners and pick the active one for issuance.
- As an admin, I can create/delete provisioners (requires remote management).

## Functional requirements

- FR-1: List provisioners from the CA (`GET {ca}/provisioners`); no admin needed.
- FR-2: Select an active provisioner; persist its name and (sealed) secret.
- FR-3: Create a provisioner via admin API (`POST /admin/provisioners`) with an
  SDK-signed admin token; validate name (`^[a-zA-Z0-9._-]+$`) and type
  (JWK/ACME/SSHPOP); JWK secret ≥ 8 chars.
- FR-4: Delete a provisioner (`DELETE /admin/provisioners/{name}`); refuse to delete
  the currently selected one.
- FR-5: All create/select/delete actions write an audit event (0009).
  **Deferred to spec/0009**: the audit subsystem is built there. No audit table or
  recorder is added in 0005; this FR has no acceptance criterion here.

## Data model

- Reuse `ca_settings` for the selected provisioner (name + sealed secret), and
  extend it (migration `0004_provisioners.sql`, ADR-0012) with the admin
  credential needed to sign x5c admin tokens: `admin_cert_pem` (the public x5c
  chain) and `admin_key_sealed` (the sealed admin private key). The spec/0004
  `admin_secret` (a password) cannot sign admin tokens; admin operations require
  this asymmetric credential.

## Admin token (ADR-0012)

- Create/delete authenticate with an x5c-signed JWT (`iss=step-admin-client/1.0`,
  `sub=<admin leaf CN>`, `aud=<endpoint URL>`, `jti`, short validity), signed via
  `go.step.sm/crypto/jose` with the admin private key; the admin chain rides in
  the `x5c` header. The token is placed verbatim in the `Authorization` header.
  Signing is validated by a mock CA in tests (no live-CA validation).

## Routes / UI

- `GET /provisioners`, `POST /provisioners` (create), `POST /provisioners/select`,
  `POST /provisioners/{name}` (delete via `action=delete`)

## Acceptance criteria

- Given a reachable CA, When I open Provisioners, Then I see the list with types.
- Given I select a JWK provisioner with its password, Then issuance uses it.
- Given valid admin creds, When I create a provisioner, Then it appears in the list.
- Given a provisioner is selected, When I try to delete it, Then I get an error.
- Given invalid admin creds, When I create, Then a clear error is shown.

## Tests

- list parsing; select persistence + sealing; admin-token signing; create/delete
  against a mock admin API; "cannot delete active" guard.

## Out of scope

- ACME-specific options and EAB (0010).
