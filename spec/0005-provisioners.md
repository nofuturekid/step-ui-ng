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

## Data model
- Reuse `ca_settings` for the selected provisioner (name + sealed secret).

## Routes / UI
- `GET /provisioners`, `POST /provisioners` (create), `POST /provisioners/select`,
  `DELETE /provisioners/{name}`

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
