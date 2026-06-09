-- +goose Up
-- Remove the vestigial CA-settings admin identity fields. They were an early
-- placeholder (0003) that nothing ever read: certificate issuance uses the
-- selected provisioner (0005), and admin-API auth uses the configurable
-- admin-authentication methods (0012, migration 0006). Keeping them only
-- duplicated those inputs confusingly.
ALTER TABLE ca_settings DROP COLUMN admin_provisioner;
ALTER TABLE ca_settings DROP COLUMN admin_subject;
ALTER TABLE ca_settings DROP COLUMN admin_secret_sealed;

-- +goose Down
ALTER TABLE ca_settings ADD COLUMN admin_provisioner TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_subject TEXT;
ALTER TABLE ca_settings ADD COLUMN admin_secret_sealed TEXT;
