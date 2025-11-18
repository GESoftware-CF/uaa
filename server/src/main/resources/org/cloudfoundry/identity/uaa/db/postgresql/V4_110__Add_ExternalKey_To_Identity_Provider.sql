-- add column external_key for oauth2,oidc,saml2 IdPs
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='identity_provider' AND column_name='external_key'
    ) THEN
ALTER TABLE identity_provider ADD COLUMN external_key VARCHAR(512) DEFAULT NULL;
END IF;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS external_key_in_zone on identity_provider (identity_zone_id,type,external_key) WHERE external_key IS NOT NULL;