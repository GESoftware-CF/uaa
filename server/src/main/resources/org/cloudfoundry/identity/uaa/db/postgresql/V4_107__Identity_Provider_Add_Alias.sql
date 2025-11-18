-- add columns for alias-id and alias-zone-id
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='identity_provider' AND column_name='alias_id'
    ) THEN
ALTER TABLE identity_provider ADD COLUMN alias_id VARCHAR(36) DEFAULT NULL;
END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='identity_provider' AND column_name='alias_zid'
    ) THEN
ALTER TABLE identity_provider ADD COLUMN alias_zid VARCHAR(36) DEFAULT NULL;
END IF;
END$$;