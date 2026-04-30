-- Flyway migration: remove unused columns from background_image_metadata (MySQL)
-- Only uploaded_at and uploaded_by are needed for audit; S3 provides the rest on demand.
-- Guarded: no-op on fresh installs where the table does not exist yet.
SET @table_exists := (
    SELECT COUNT(*)
    FROM   information_schema.tables
    WHERE  table_schema = DATABASE()
      AND  table_name   = 'background_image_metadata'
);

SET @sql := IF(
    @table_exists > 0,
    'ALTER TABLE background_image_metadata
         DROP COLUMN IF EXISTS original_filename,
         DROP COLUMN IF EXISTS content_type,
         DROP COLUMN IF EXISTS file_size',
    'SELECT 1 -- background_image_metadata does not exist; skipping'
);

PREPARE _stmt FROM @sql;
EXECUTE _stmt;
DEALLOCATE PREPARE _stmt;

