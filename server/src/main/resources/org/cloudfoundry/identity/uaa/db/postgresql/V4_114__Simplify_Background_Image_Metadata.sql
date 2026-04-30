-- Flyway migration: remove unused columns from background_image_metadata (PostgreSQL)
-- Only uploaded_at and uploaded_by are needed for audit; S3 provides the rest on demand.
-- Guarded: no-op on fresh installs where the table does not exist yet.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name   = 'background_image_metadata'
    ) THEN
        ALTER TABLE background_image_metadata
            DROP COLUMN IF EXISTS original_filename,
            DROP COLUMN IF EXISTS content_type,
            DROP COLUMN IF EXISTS file_size;
    END IF;
END
$$;

