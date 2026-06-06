# 0007 — Inventory & encrypted re-download

## Context
Browse issued certificates and re-download bundles at any time. Private keys are
stored **encrypted** (ADR-0006) so re-download (incl. key) stays possible without
clear-text at rest.

## User stories
- As a user, I list/filter/search certificates and view details.
- As a user, I download a certificate bundle (cert/chain/fullchain[/key][/p12]).

## Functional requirements
- FR-1: Inventory list with filters (status, search by CN/SAN) and a detail view.
- FR-2: Status derivation: active / expired / revoked; days-until-expiry.
- FR-3: Download a ZIP: `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`
  (only if a key is stored), optional `cert.p12` (PFX with password), `README.txt`.
- FR-4: Stored private keys are sealed (0002); decrypted only in-memory to build the
  download; never written to disk in clear text.
- FR-5: Offer a **download now** action immediately after issuance (0006), and a
  download in both the inventory row and the detail view (discoverable, labelled —
  not just a tiny icon).
- FR-6: CSR-signed certificates download without `privkey.pem`.

## Routes / UI
- `GET /inventory`, `GET /certificates/{id}`, `GET /certificates/{id}/download`

## Acceptance criteria
- Given a server-issued certificate, When I download it, Then the ZIP contains
  cert/chain/fullchain and the private key.
- Given a CSR-signed certificate, When I download it, Then the ZIP omits the key.
- Given stored material, When I inspect the DB, Then the private key is encrypted
  (not clear text).
- Given filters, When I filter by status/search, Then the list updates accordingly.

## Tests
- bundle contents per key strategy; sealed-at-rest assertion; filter logic;
  expiry/status derivation.

## Out of scope
- Revoke/renew actions (0008).
