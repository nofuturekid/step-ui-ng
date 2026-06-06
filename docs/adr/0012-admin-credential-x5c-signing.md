# 0012. Admin operations use an x5c-signed token from a stored admin certificate + sealed key

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement

Spec/0005 (provisioner management) needs to create and delete provisioners via
Step-CA's admin API (`POST /admin/provisioners`, `DELETE /admin/provisioners/{name}`).
Those endpoints authenticate each request with an SDK-signed **admin token**
(ADR-0004), not a password. Spec/0004 modelled the admin credential as a single
sealed `admin_secret` (a password). That is insufficient: signing an admin token
requires asymmetric key material — a certificate chain and the matching private
key — which the spec/0004 schema does not carry.

## Decision Drivers

- ADR-0004: talk to Step-CA via the SDK/HTTP admin API, signing admin tokens with
  `go.step.sm/crypto` — never the `step` CLI.
- ADR-0006: no private key or secret in clear text at rest.
- Testability: the token must be verifiable by a mock that mirrors Step-CA.
- Keep the binary self-contained: avoid pulling the heavy
  `smallstep/certificates` + `linkedca` proto runtime in just to build a request.

## Considered Options

- **(A)** Extend `ca_settings` with an admin certificate chain (PEM, public) and a
  sealed admin private key; sign the x5c admin token ourselves with
  `go.step.sm/crypto/jose`.
- **(B)** Reuse the existing `admin_secret` password and have the UI mint a JWK
  token. Step-CA's admin API does not accept a JWK-provisioner token for admin
  operations — it requires an x5c admin token — so this does not work.
- **(C)** Depend on `smallstep/certificates`' `ca.AdminClient` to build/sign the
  request for us.

## Decision Outcome

Chosen option: **(A)**. The admin token is an x5c-signed JWT built and signed with
`go.step.sm/crypto/jose`, exactly matching what Step-CA's
`authority.AuthorizeAdminToken` validates. We add four nullable columns to the
single-row `ca_settings` table (migration `0004_provisioners.sql`):

- `selected_provisioner` and `selected_provisioner_secret_sealed` — the active
  provisioner for issuance (FR-2); the secret is sealed (AES-256-GCM, ADR-0006).
- `admin_cert_pem` — the admin certificate chain (leaf first). This is **public**
  (it travels in the token's `x5c` header) so it is stored verbatim.
- `admin_key_sealed` — the admin **private** key (PEM), sealed before storage and
  decrypted only inside the process for signing. It is write-only toward the
  client (the `View` exposes only `HasAdminKey`), following the FR-5 pattern.

### Token format (validated against a mock, not a live CA)

A compact JWS, placed verbatim in the `Authorization` header (no `Bearer`
prefix), with header `typ=JWT` and `x5c=[base64(DER) leaf-first]`, and claims:
`iss="step-admin-client/1.0"`, `sub=<leaf CN>`, `aud=<full endpoint URL>`,
`jti=<random hex>`, and a short `iat/nbf/exp` window. Step-CA verifies the x5c
chain to its root (clientAuth EKU), requires the leaf's digital-signature key
usage, verifies the JWS with the leaf public key, and checks time/aud/iss/sub.
The unit tests stand up an `httptest` mock that re-implements those checks with
the public key, so they prove the token is signed and shaped correctly; they do
**not** prove behaviour against a live Step-CA (remote management config, admin
enrolment and DB-backed token reuse are only observable there).

### Consequences

- Good: matches the real admin-token format; no `step` CLI; no clear-text key at
  rest; signing is unit-testable.
- Good: avoids pulling the `linkedca`/`certificates` proto runtime — the create
  body is built as the documented protojson shape directly.
- Bad: the operator must supply an admin certificate + key (an extra setup step
  beyond a password). This is inherent to the admin API.
- Neutral: requires the CA's remote provisioner management to be enabled.

## More Information

- Supersedes the spec/0004 assumption that `admin_secret` alone suffices for
  admin operations; the password column remains for other uses. Spec/0004 and
  spec/0005 wording updated to reflect the extra credential.
- Audit events for provisioner actions (FR-5 of 0005) are deferred to spec/0009.
- Sources: `smallstep/certificates` `authority/authorize.go`
  (`AuthorizeAdminToken`), `ca/adminClient.go` (`generateAdminToken`),
  `go.step.sm/crypto/jose`, and `smallstep/linkedca` `provisioners.proto`.
