# 0006. Encrypt secrets at rest; master key stored next to the database

- Status: accepted
- Date: 2026-06-06
- Deciders: maintainer

## Context and Problem Statement
The predecessor stored private keys and provisioner/admin secrets in clear text in
SQLite. We want re-downloadable bundles without clear-text secrets, and minimal env.

## Decision Drivers
- No clear-text secrets/keys at rest.
- Few/zero environment variables (maintainer preference).

## Considered Options
- Auto-generated master key file next to the DB in the data volume
- Single env var (APP_SECRET_KEY)
- Derive key from the super-admin password

## Decision Outcome
Chosen option: "Auto-generated `secret.key` in the data dir" (0600), used for
AES-256-GCM encryption of secrets and stored private keys. Optional env override
may be added later.

### Consequences
- Good, because zero env config; encryption by default.
- Bad, because whoever holds the volume holds DB + key — so the volume must be
  protected and excluded from unprotected backups.
- Neutral, documented as an accepted homelab trade-off.

## More Information
See spec 0002. Consider an env/KMS override as a future ADR if threat model grows.
