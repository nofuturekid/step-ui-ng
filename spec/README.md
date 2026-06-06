# Specifications (Spec-Driven Development)

Each feature is specified before it is built. Implement specs in numeric order.

## Spec format

Every spec contains:

- **Context** — why this exists.
- **User stories** — who needs what, and why.
- **Functional requirements** — numbered (FR-1, FR-2, …).
- **Data model / Routes / UI** — what's persisted and exposed.
- **Acceptance criteria** — Given/When/Then; these become tests (TDD).
- **Tests** — the test list to write first.
- **Out of scope** — explicitly deferred.

## Definition of Done

A spec is done when all acceptance criteria are covered by passing tests,
`make check` is green, docs/ADRs are updated, and a `CHANGELOG.md` entry is added
under `[Unreleased]` (versions are bumped only at releases — ADR-0011). See
`AGENTS.md`.

## Index

1. 0001-foundation — project skeleton, config, DB+migrations, logging, health
2. 0002-crypto-secrets — master key + AES-GCM secret box
3. 0003-auth-users — first-run super-admin, login, sessions, roles, user mgmt
4. 0004-ca-settings — Step-CA connection configured & tested via the UI
5. 0005-provisioners — list, select, create, delete (admin API + SDK)
6. 0006-issue-sign — issue certificate; sign CSR (with CSR parsing)
7. 0007-inventory-download — inventory, detail, encrypted re-download (cert+key+chain)
8. 0008-revoke-renew — real revocation via CA; configurable renew
9. 0009-audit — audit log with filters and authenticated actor
10. 0010-acme — ACME provisioners, EAB keys, directory + client onboarding

## Feature-parity checklist (must match predecessor, then improve)

- [ ] Issue certificate (CN, SANs, validity, PEM/PFX)
- [ ] Sign CSR (parse CN/SANs from the CSR)
- [ ] Inventory (list/filter/detail)
- [ ] Download bundle (cert/chain/fullchain/key; key encrypted at rest)
- [ ] Provisioner list + select + create + delete
- [ ] Audit log (filterable)
- [ ] CA settings (managed in UI)
- [ ] Renew + **real** revoke
- [ ] NEW: built-in auth + users; ACME management
