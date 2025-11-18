DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='oauth_client_details' AND column_name='client_jwt_config'
    ) THEN
ALTER TABLE oauth_client_details ADD COLUMN client_jwt_config TEXT DEFAULT NULL;
END IF;
END$$;
