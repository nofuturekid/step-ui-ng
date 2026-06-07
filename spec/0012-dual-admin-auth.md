# 0012 — Dual admin authentication (x5c cert + JWK/password)

## Context

Provisioner create/delete (0005) and ACME/EAB management (0010) authenticate to
Step-CA's Admin API with an **x5c admin token** — signed by an admin **certificate +
private key** (`ca.AdminCredential`, ADR-0012). Two problems surfaced in real use:

1. **The x5c credential cannot be entered.** `settings.Repo.SaveAdminCredential` exists
   and `adminCredential`/`HasAdminKey` load it, but **no route or form ever calls
   Save** — and the CA-settings page has no cert/key field. So `HasAdminKey` is always
   false and the UI permanently shows "add an admin certificate and key on the CA
   settings page", pointing at a field that does not exist. Create/delete and ACME
   management are unreachable from the UI.
2. **Real remote-management CAs are JWK/password-based.** `step ca init
--remote-management` provisions a **JWK super-admin** by default — the operator gets
   a **password**, not a certificate. The app's x5c-only path cannot use that password
   for admin operations (only for issuance, as the JWK provisioner OTT secret).

This spec makes the admin authentication **configurable**, with two methods behind a
common abstraction, so the operator picks what fits their CA:

- **(B) x5c certificate** — _guided_: the UI shows the exact `step` commands (filled
  with the stored CA URL + root fingerprint) to create an x5c admin and issue its
  cert/key, plus an upload for the result. The app reuses its existing x5c token signer.
- **(C) JWK / password** — _direct_: the operator enters an admin subject + the admin's
  JWK provisioner + that provisioner's password; the app fetches the provisioner's
  published `encryptedKey` from `/provisioners`, decrypts it in-memory with the
  password, and signs a JWK admin token. No certificate, no CA-host steps.

## User stories

- As an admin, I choose how this UI authenticates to my CA's Admin API — upload an
  admin cert/key (with the UI telling me exactly how to create them), **or** point it
  at my JWK admin with its password — and then create/delete provisioners and manage
  ACME from the UI.
- As an admin with a default `--remote-management` CA, I can manage provisioners using
  only the **password** I already have, without generating any certificate.

## Functional requirements

- **FR-1 (method selector):** the CA-settings page gains an **Admin authentication**
  card with a method selector: `none` (default), `x5c` (certificate), `jwk` (provisioner
  password). The page shows which method is active and whether it is fully configured.
- **FR-2 (x5c, guided + upload):** when `x5c` is chosen, show a panel with **copyable
  `step` commands** pre-filled from the stored CA URL + root fingerprint (create an X5C
  provisioner trusting the root, register a super-admin subject, issue an admin cert+key
  with clientAuth EKU), and an **upload** for the admin **certificate chain (PEM)** +
  **private key (PEM)**. Wire `SaveAdminCredential`. The key is **sealed** at rest
  (ADR-0006), write-only, never echoed; validate keypair match, clientAuth/digital-
  signature usage, and a non-empty leaf CN. A status badge shows configured/empty.
- **FR-3 (JWK, in-app signing):** when `jwk` is chosen, fields are **admin subject** +
  **admin provisioner** (chosen from the CA's JWK provisioners) + **password** (sealed,
  write-only, badge). At admin-operation time the app fetches the named JWK
  provisioner's `encryptedKey`/`kid` from `/provisioners` over the pinned client,
  decrypts in-memory with the password, and signs a JWK admin token (correct
  `iss`/`kid`/`sub`/`aud` for Step-CA's `AuthorizeAdminToken`).
- **FR-4 (common abstraction):** introduce an `AdminAuth` token source —
  `AdminToken(ctx, endpoint) (string, error)` — with `x5cAuth` and `jwkAuth`
  implementations. `CreateProvisioner`/`DeleteProvisioner` (0005) and the ACME/EAB admin
  calls (0010) take this source instead of a concrete `AdminCredential`; their request
  flow is otherwise unchanged. Exactly one method is active (the configured one).
- **FR-5 (switching is clean):** changing the method clears the other method's stored
  secret material (no stale sealed key/password lingering).
- **FR-6 (honest UI):** replace the current misleading hints. When no method is
  configured, the create/delete and ACME-manage controls are disabled with a clear
  message that names both options (configure admin auth here) **and** the CLI
  alternative (`step ca provisioner add …` works with the JWK password without any
  app config).
- **FR-7 (security):** the admin private key and the JWK password are sealed
  (AES-256-GCM) and never logged, echoed, or written to audit detail. Admin tokens and
  the decrypted JWK key live only in memory and are never logged. All admin calls reuse
  the root-fingerprint-pinned client (no blanket skip-verify).

## Routes / UI

- Extends `GET /settings` (the Admin-authentication card) and `GET /provisioners` /
  `GET /acme` (enable management controls only when admin auth is configured).
- New POST handlers to save the chosen method + its material (e.g.
  `POST /settings/admin-auth`), audited on success (non-secret detail only, 0009).
- No change to the Admin-API request shape itself (still x5c/JWK JWT in the
  `Authorization` header).

## Acceptance criteria

- Given a valid **x5c** cert+key configured, When I create a provisioner in the UI,
  Then it is created on the CA (admin token accepted).
- Given **jwk** configured (subject + JWK provisioner + password), When I create a
  provisioner in the UI, Then it is created on the CA.
- Given **no** admin auth, Then create/delete and ACME-manage controls are disabled with
  guidance (UI + the CLI alternative); listing/selecting/issuing still work.
- Given either method, When I inspect the DB or any rendered page or log, Then the
  private key / password is sealed and never exposed; a set/empty badge reflects state.
- Given I switch method, Then the previous method's secret is cleared.
- Verified **end-to-end against a real Step-CA** — at minimum the **JWK** path against
  the maintainer's `--remote-management` CA; the x5c path if a cert is available.

## Tests

- `internal/ca`: JWK admin-token generation against an httptest mock CA that publishes a
  JWK provisioner (`encryptedKey`/`kid`) and asserts the token's `iss`/`kid`/`sub`/`aud`
  - signature; create/delete and EAB exercised through both `x5cAuth` and `jwkAuth`
    (the x5c path already has tests). Wrong password → typed error, not a leak.
- `internal/settings`: store/seal/clear admin-auth material; `HasAdminKey` /
  `HasAdminJWK`-style flags; switching method clears the other's secret.
- `internal/app`: settings page renders the method selector, the **CA-tailored** x5c
  command snippet, and the JWK fields; secrets never echoed; provisioner/ACME management
  controls gated on configured auth.
- **Real-CA smoke** (throwaway, like the 0011/CA-fix verification): a generated JWK admin
  token is accepted by the live CA for a read-only admin call; deleted after.

## Out of scope

- OIDC-based admin auth; managing admins/authorities themselves; auto-creating the X5C
  provisioner or admin (the UI only _shows_ the commands — the operator runs them).
- Non-JWK provisioner-password admins (ACME/SCEP/etc. as admin auth).

## Notes

- **Assumptions to verify at implementation (against the step-ca SDK + the maintainer's
  live CA), flagged like 0011's CA-wire assumptions:**
  1. The exact JWK **admin-token** format `AuthorizeAdminToken` accepts (claims, `kid`
     vs `iss=provisioner-name`, signature alg) and how the `encryptedKey` is decrypted
     (the SDK's scrypt/JWE scheme).
  2. The exact **x5c command sequence** (X5C provisioner ↔ admin subject ↔ cert/EKU)
     so the shown commands actually work — not guesses.
- Architecture decision recorded as **ADR-0018** (the `AdminAuth` abstraction + the two
  methods + rationale: x5c was the only path and unreachable; JWK/password is the
  default remote-management admin; mock≠real, see [[ca-pinning-mock-vs-real]]).
- `CHANGELOG.md` under `[Unreleased]`; no version bump (ADR-0011). The honest-hints part
  of FR-6 may ship first as a small standalone fix.
- Builds on 0004 (CA settings), 0005 (provisioner mgmt / x5c), 0010 (ACME), ADR-0012
  (x5c admin signing), ADR-0006 (sealing). Spec 0011 (CRL) reserves **ADR-0017**.
