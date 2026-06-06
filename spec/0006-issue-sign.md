# 0006 — Issue certificate & sign CSR

## Context
Core issuance: request a server-generated certificate, or sign a client CSR, via
the CA using the active provisioner (ADR-0004).

## User stories
- As a user, I issue a certificate for a CN with optional SANs and a validity.
- As a user, I sign a CSR I paste/upload, and the CN/SANs are taken from the CSR.

## Functional requirements
- FR-1: Issue: inputs CN, SANs[], validity (days, bounded by the provisioner max),
  format (PEM bundle or PFX with password). Server obtains a token via the active
  provisioner and requests the certificate from the CA.
- FR-2: Sign CSR: parse the PEM CSR with `crypto/x509`; extract CN + SANs (DNS/IP/
  email/URI); verify the CSR signature before sending to the CA.
- FR-3: Persist certificate metadata + PEM material (see 0007 for storage/encryption).
- FR-4: Write an audit event with the authenticated actor (0009).
- FR-5: Clear validation errors (bad CSR, validity over max, missing provisioner).

## Data model
- `certificates(id, cn, sans_json, serial, not_before, not_after, status,
  key_strategy[server|csr], cert_pem, chain_pem, fullchain_pem,
  privkey_sealed NULLABLE, created_by, created_at, updated_at)`

## Routes / UI
- `GET /issue`, `POST /issue`
- `GET /sign-csr`, `POST /sign-csr`

## Acceptance criteria
- Given an active provisioner, When I issue for `example.test` with a SAN, Then a
  certificate is created and stored, and appears in the inventory.
- Given a validity greater than the provisioner max, When I issue, Then it is
  rejected with a clear message.
- Given a valid CSR, When I sign it, Then CN/SANs are taken from the CSR and a
  certificate (without private key) is stored.
- Given an invalid/garbled CSR, When I sign, Then it is rejected.

## Tests
- CSR parsing (CN/SANs, signature check); issue/sign against a mock CA; validity
  bounds; audit actor recorded.

## Out of scope
- Re-download UX (0007); revoke/renew (0008).
