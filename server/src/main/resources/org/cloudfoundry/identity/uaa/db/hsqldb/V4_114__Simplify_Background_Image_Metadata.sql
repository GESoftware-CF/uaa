-- Flyway migration: remove unused columns from background_image_metadata (HSQLDB)
-- Only uploaded_at and uploaded_by are needed for audit; S3 provides the rest on demand.
ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS original_filename;
ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS content_type;
ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS file_size;

