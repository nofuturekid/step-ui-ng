-- +goose Up
-- Record the provisioner name used when issuing or signing a certificate
-- (backlog item ②). Nullable so existing rows remain valid (NULL → "—" in the
-- inventory UI). New issuances/signings write the active provisioner name here.
ALTER TABLE certificates ADD COLUMN provisioner TEXT;

-- +goose Down
ALTER TABLE certificates DROP COLUMN provisioner;
