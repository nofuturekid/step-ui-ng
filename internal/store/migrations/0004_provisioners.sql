-- +goose Up
-- Extend the single-row ca_settings table for provisioner management (spec/0005,
-- ADR-0012). Two distinct concerns are added:
--
--   1. The *selected* provisioner used for issuance (FR-2): its name plus an
--      optional sealed secret (e.g. the JWK provisioner password). The secret is
--      sealed (AES-256-GCM, ADR-0006) before storage: the column holds
--      base64(nonce ‖ ciphertext), never clear text.
--
--   2. The admin credential used to sign x5c admin tokens for create/delete
--      (FR-3/FR-4). Admin-token signing needs key material beyond the spec/0004
--      admin_secret (a password): an admin certificate chain (public, carried in
--      the JWT x5c header) and the matching private key (used to sign, and thus
--      sealed at rest). admin_cert_pem is the PEM chain (leaf first); the leaf
--      must chain to the CA root and carry the digital-signature key usage and
--      clientAuth EKU. admin_key_sealed is the sealed PEM private key.
--
-- All four columns are nullable: provisioner selection and admin management are
-- independent and either may be unconfigured.
ALTER TABLE ca_settings ADD COLUMN selected_provisioner TEXT;
ALTER TABLE ca_settings ADD COLUMN selected_provisioner_secret_sealed TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_cert_pem TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_key_sealed TEXT;

-- +goose Down
ALTER TABLE ca_settings DROP COLUMN selected_provisioner;
ALTER TABLE ca_settings DROP COLUMN selected_provisioner_secret_sealed;
ALTER TABLE ca_settings DROP COLUMN admin_cert_pem;
ALTER TABLE ca_settings DROP COLUMN admin_key_sealed;
