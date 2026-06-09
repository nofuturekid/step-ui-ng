# 0018. Configurable admin authentication: one x5c token, two credential sources

- Status: accepted
- Date: 2026-06-09
- Deciders: maintainer

## Context and Problem Statement

The app's admin operations (provisioner create/delete — 0005; ACME/EAB — 0010)
authenticate to Step-CA's Admin API with an x5c admin token signed by an admin
certificate + key (`ca.generateAdminToken`, ADR-0012). Two gaps surfaced in real use
(spec/0012): the x5c credential can never be entered (`SaveAdminCredential` has no
caller, no form field), and a default `step ca init --remote-management` CA hands the
operator a **JWK super-admin password**, not a certificate — which the app could not use
for admin operations at all.

The original plan (spec/0012 FR-3) assumed the password could sign a **"JWK admin
token"**. Verifying against the maintainer's live CA disproved this.

## Decision Drivers

- Make admin auth configurable so an operator can use whatever their CA gave them — an
  uploaded admin cert/key **or** a JWK provisioner password — and actually reach the
  provisioner/ACME management UI.
- Be correct against a real Step-CA, not a mock (the mock≠real lesson, see
  ADR for the CA-pinning fix and the [[ca-pinning-mock-vs-real]] memory).
- Reuse the existing, tested x5c token signer; minimise new crypto surface.
- Never persist or log secrets; sealed at rest (ADR-0006); pinned client only.

## Considered Options

- **Two token types** — an x5c signer and a separate "JWK admin token" signer behind an
  `AdminToken()` abstraction (spec/0012 FR-3 as originally written).
- **One x5c token, two credential sources** — keep the single x5c signer; vary only where
  the admin cert+key come from (uploaded vs. minted from the JWK password).
- **JWK/password only** (drop x5c upload) or **x5c upload only** (drop JWK) — a single method.

## Decision Outcome

Chosen option: **one x5c token, two credential sources**, because Step-CA's
`AuthorizeAdminToken` accepts **only** x5c tokens — there is no JWK admin token, so a
second token type is impossible, not merely undesirable.

Verified against the live CA (2026-06-09): `authority/authorize.go` only validates an
x5c chain, and `ca/adminClient.go` always sets `WithX5CCerts`. A JWK/password admin works
by using the provisioner key to **mint a short-lived admin certificate** and then signing
the normal x5c token with it. Confirmed end-to-end via `step ca admin list` on the
maintainer's CA (super-admin subject `step`, JWK provisioner `admin`, SUPER_ADMIN).

The design is therefore an `AdminAuth` **credential source** yielding a
`ca.AdminCredential`:

- `x5cStored` — the uploaded, sealed admin cert chain + key (wires `SaveAdminCredential`).
- `jwkMinted` — decrypt the JWK provisioner's published `encryptedKey` with the sealed
  password, sign a provisioner OTT, mint a cert via `POST /1.0/sign` for the admin
  subject, and use that ephemeral cert+key.

Both feed the unchanged `generateAdminToken` (x5c). Exactly one method is active; switching
clears the other's sealed secret.

### Consequences

- Good, because the token-signing path (the security-critical part) is unchanged and
  already tested.
- Good, because a default remote-management CA is usable with just the password the
  operator already has — no certificate, no CA-host steps.
- Good, because the design is validated against a real CA, not assumed.
- Neutral, the JWK path performs an extra `/1.0/sign` round-trip per admin operation (a
  short-lived minted cert); acceptable for infrequent admin actions, and may be cached
  within the cert's short validity later if needed.
- Bad, because the JWK path is more moving parts (OTT + CSR + sign) than a static upload;
  contained in `internal/ca` behind the credential-source interface.

## Pros and Cons of the Options

### Two token types

- Good, because conceptually symmetric (a signer per method).
- Bad, because **impossible** — the CA has no JWK admin-token validation path.

### One x5c token, two credential sources

- Good, because it matches what the CA actually accepts and reuses the x5c signer.
- Good, because the methods differ only in credential origin — a small, testable seam.
- Bad, because the JWK source must replicate the provisioner OTT → sign flow.

### Single method only

- Good, because least code.
- Bad, because it abandons either the upload operators or the (more common)
  remote-management/password operators.

## More Information

- Spec: [`spec/0012-dual-admin-auth.md`](../../spec/0012-dual-admin-auth.md).
- Builds on ADR-0012 (x5c admin signing), ADR-0006 (sealing). Spec 0011 (CRL) reserves
  ADR-0017.
- Live-CA findings recorded in the spec Notes and the `specs-complete-pending-release`
  memory; mock≠real rationale in [[ca-pinning-mock-vs-real]].
