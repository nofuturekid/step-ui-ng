# 0011 — Live revocation status (CRL) & inventory truthfulness

## Context

The inventory (0007) lists certificates from the **local DB**, not the CA — it is an
operational record of what was issued/managed **through this UI**, not a live mirror
of the CA. Two truth gaps follow:

1. **Revocation staleness** — a certificate revoked _outside_ this UI (another admin,
   `step ca revoke`, an ACME client) keeps showing as active, because the stored
   `status` is only set when _this_ app revokes (0008).
2. **Incompleteness** — certificates issued outside this UI (CLI, ACME, other clients)
   never appear at all.

Pre-clarification on what the CA offers (open-source step-ca):

- **No OCSP responder** — Smallstep positions active revocation as a commercial
  feature; OSS step-ca has no OCSP endpoint.
- **CRL is available** — a public `GET /crl` (DER, no auth), **opt-in** via the `crl`
  block in `ca.json` (`enabled`, `generateOnRevoke`, `cacheDuration`, `idpURL`). The
  default model is _passive revocation_ (short-lived certs), so many deployments have
  CRL turned off.

Therefore this spec closes gap (1) via **CRL where the CA exposes it** (degrading
silently when it does not), and makes gap (2) **honest in the UI** rather than
pretending the list is the CA's full live state. OCSP and completeness are out of
scope (see below).

## User stories

- As a user, I see when a listed certificate has been **revoked at the CA**, even if
  it was revoked outside this UI.
- As a user, I understand the inventory is a **record of certs managed via this UI**,
  with a visible _last-synced_ indication, so I do not mistake it for the CA's
  complete live state.

## Functional requirements

- **FR-1 (fetch + parse):** add `ca.FetchCRL(ctx, caURL, fingerprint)` that GETs
  `<caURL>/crl` over the **existing root-fingerprint-pinned client**
  (`pinnedClientFor`/`fetch`), parses the DER with `crypto/x509.ParseRevocationList`,
  and returns the set of revoked serials plus `thisUpdate`/`nextUpdate`. No admin
  token (the endpoint is public).
- **FR-2 (display-only overlay):** at **read time**, a stored certificate whose serial
  appears in the CRL is shown as `revoked`. The stored `status` column is **never**
  mutated by this check (stored status stays "what this UI did"); revocation is
  derived for display only — so the overlay cannot re-introduce drift. Serial
  comparison is canonicalized (parse both sides to `big.Int` / normalize hex, handle
  leading zeros and case). **Assumption to verify** at implementation (against a real
  step-ca): the exact serial encoding step-ca emits in its CRL.
- **FR-3 (single fetch + cache):** a CRL is **one document for the whole CA**, not a
  per-certificate lookup. Fetch it **once per render**, cached in-memory keyed by CA
  URL and honoring `nextUpdate` (bounded by a short TTL). Rendering N rows triggers at
  most one upstream `/crl` fetch.
- **FR-4 (graceful degradation):** if `/crl` is 404 / unreachable / disabled, or the
  body fails to parse, the inventory **still renders**; a non-fatal notice is shown
  ("live revocation check unavailable — CRL not enabled on this CA"). The check must
  never fail the page or block any other flow. The handler treats **any** non-`200` /
  non-parseable result as "unavailable", so it is robust regardless of the exact
  disabled-CRL response. **Assumption to verify** at implementation (against a real
  step-ca): what `/crl` returns when CRL is disabled (`404` vs an empty CRL).
- **FR-5 (truthfulness affordance):** the inventory list and the certificate detail
  view carry a clear note that this is a record of certs managed via this UI — _status
  as recorded_ — plus "CRL last synced: <ts>" when a check succeeded, or the
  unavailable notice from FR-4 otherwise.
- **FR-6 (status precedence):** on display, precedence is
  `revoked` (CRL or stored) > `expired` (from `notAfter`) > `expiring` > `active`.
  Expiry stays derived from the immutable `notAfter` (already correct today).
- **FR-7 (security):** the CRL fetch reuses the pinned transport — **no new trust
  path**, no `InsecureSkipVerify`. The CRL is public, so no secrets/credentials are
  involved and nothing is logged/audited from it.

## Routes / UI

- **No new routes.** Extends the rendering of `GET /inventory` (incl. the htmx table
  partial) and `GET /certificates/{id}`; adds `ca.FetchCRL` in the `ca` package and a
  small in-memory CRL cache.

## Acceptance criteria

- Given a CA with CRL enabled and a cert revoked **out-of-band**, When I open the
  inventory, Then that row shows `revoked`.
- Given a CA without `/crl`, When I open the inventory, Then it renders normally with a
  "revocation check unavailable" notice and **no error/500**.
- Given a successful CRL check, When I view the inventory/detail, Then a "CRL last
  synced <ts>" indication is shown.
- Given a cert shown `revoked` via overlay, When I inspect the DB, Then the stored
  `status` is **unchanged** (overlay is display-only).
- Given the same CA, When the inventory renders twice within the cache TTL, Then
  `/crl` is fetched **at most once**.
- Given a revoked **and** expired cert, When I view it, Then it shows `revoked`
  (precedence, FR-6).

## Tests

- httptest mock CA serving `/crl` as a DER CRL built with `x509.CreateRevocationList`
  containing a known serial → that serial renders `revoked`; an absent serial keeps
  its stored/derived status.
- `/crl` returns 404 → degrades, notice shown, no 500.
- malformed CRL body → degrades (same path).
- serial canonicalization: hex vs decimal, leading zeros, case → still matches.
- cache: two renders → exactly one upstream `/crl` request (assert via request count
  on the mock).
- precedence: revoked beats expired/expiring; expiry-only unchanged.
- DB assertion: stored `status` untouched after an overlay render.

## Out of scope

- **OCSP** — not available in OSS step-ca (see _Future extensions_).
- **Completeness** — enumerating certs issued outside this UI; OSS step-ca has no
  list endpoint (see _Future extensions_).
- **Persisting revocation** or a **scheduled background CRL refresh** — read-time +
  in-memory cache only here (see _Future extensions_).

## Future extensions (recorded findings — not built in this spec)

These came out of the design discussion; recorded so they are not re-discovered later.

- **Complete inventory via webhook ingestion (push, not poll).** OSS step-ca cannot be
  _queried_ for its full issued set: it persists issued certs (serial, DER, timestamp)
  and exposes per-serial retrieval (`GET /cert/{serial}`, the `certUrl` from the
  issuance response) and the CRL (`/crl`), but there is **no enumerate-all / list
  endpoint**. The way the official/commercial Smallstep product builds a full inventory
  is to record issuances as **events**, not by polling. A future spec could make this
  app a **provisioner-webhook receiver** so externally-/ACME-issued certs land in the
  inventory at issue time. _Prerequisite to verify against a real step-ca:_ that the
  webhook payload actually carries the issued certificate/serial (step-ca webhooks are
  primarily enrich/authorize hooks). Larger, separate feature; different design from CRL.
- **Per-serial verification via `GET /cert/{serial}`.** Since we store serials, a future
  enhancement could fetch a stored cert's canonical record from the CA by serial — e.g.
  confirm the CA still recognizes it, or surface a mismatch. Does **not** provide
  enumeration, and revocation still comes from the CRL (the returned cert bytes are
  static and carry no revocation state).
- **Persisted revocation status / scheduled background CRL refresh.** This spec keeps
  revocation read-time with an in-memory cache; a later optimization could persist the
  last-known revocation set and refresh on a schedule, for resilience to CA downtime and
  to decouple page loads from a CA round-trip.
- **OCSP.** Not in OSS step-ca; would only become relevant on Smallstep's commercial
  product (which offers active revocation incl. OCSP).

## Notes

- The architecture decision (CRL-only vs OCSP; display-overlay vs persisted status;
  graceful degradation; pinned-transport reuse) is recorded as **ADR-0016** alongside
  the implementation.
- CHANGELOG under `[Unreleased]`; no version bump until a release (ADR-0011).
- Builds on 0007 (inventory), 0008 (revoke), 0004/0005 (CA connection + pinned client).
- **Verification stance:** tests run against httptest mock CAs (no live step-ca in CI,
  consistent with 0004–0010). Two CA-wire details are flagged above as assumptions to
  confirm against a real step-ca during implementation — the disabled-CRL response
  (FR-4) and the CRL serial encoding (FR-2); both are written so the code stays correct
  even if the assumption is off.
