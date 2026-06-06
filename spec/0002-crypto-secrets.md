# 0002 — Crypto & secrets at rest

## Context
All sensitive values (provisioner/admin secrets, stored private keys) must be
encrypted at rest. See ADR-0006.

## User stories
- As an operator, I never have secrets stored in clear text on disk.
- As a developer, I have a simple API to seal/open secrets.

## Functional requirements
- FR-1: On first start, generate a 32-byte master key, write `DATA_DIR/secret.key`
  with mode 0600; on later starts, load it.
- FR-2: Provide `Seal(plaintext) -> string` and `Open(ciphertext) -> plaintext`
  using AES-256-GCM with a random nonce per message; output is base64.
- FR-3: Tampered/short ciphertext fails to open with a clear error.
- FR-4: Optional: support an env override for the key source (documented, off by
  default).

## Data model
- Key file `secret.key` in `DATA_DIR` (not in the DB, never logged).

## Acceptance criteria
- Given a fresh data dir, When the app starts, Then `secret.key` is created (0600).
- Given a value, When I Seal then Open it, Then I get the original bytes back.
- Given a ciphertext with one byte flipped, When I Open it, Then it errors.
- Given an existing `secret.key`, When the app restarts, Then previously sealed
  values still open.

## Tests
- round-trip seal/open; tamper detection; key persistence across reload; file perms.

## Out of scope
- KMS/HSM integration.
