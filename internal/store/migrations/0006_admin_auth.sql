-- +goose Up
-- Add configurable admin authentication method (spec/0012, ADR-0018). The
-- operator chooses one of three methods:
--
--   none  — no admin credential; create/delete/ACME-manage are disabled.
--   x5c   — uploaded admin cert chain (admin_cert_pem) + sealed private key
--           (admin_key_sealed), added in migration 0004.
--   jwk   — JWK provisioner password: the app mints a short-lived admin cert
--           on demand via the provisioner OTT → /1.0/sign flow (FR-3).
--
-- JWK fields:
--   admin_jwk_subject     — the admin subject (CN + DNS SAN of the minted cert,
--                           e.g. "step").
--   admin_jwk_provisioner — the JWK provisioner name on the CA (e.g. "admin").
--   admin_jwk_password_sealed — the provisioner password sealed (AES-256-GCM,
--                           ADR-0006); base64(nonce ‖ ciphertext), never plain.
--
-- Switching method clears the other method's secret material (FR-5): the
-- SaveAdminJWK and SaveAdminCredential callers handle that at the app layer.
ALTER TABLE ca_settings ADD COLUMN admin_auth_method TEXT NOT NULL DEFAULT 'none';
ALTER TABLE ca_settings ADD COLUMN admin_jwk_subject TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_jwk_provisioner TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_jwk_password_sealed TEXT;

-- +goose Down
ALTER TABLE ca_settings DROP COLUMN admin_jwk_password_sealed;
ALTER TABLE ca_settings DROP COLUMN admin_jwk_provisioner;
ALTER TABLE ca_settings DROP COLUMN admin_jwk_subject;
ALTER TABLE ca_settings DROP COLUMN admin_auth_method;
