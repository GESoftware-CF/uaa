-- Flyway migration: remove unused columns from background_image_metadata (HSQLDB)
-- Only uploaded_at and uploaded_by are needed for audit; S3 provides the rest on demand.
-- Guarded: no-op on fresh installs where the table does not exist yet.
DROP PROCEDURE IF EXISTS simplify_background_image_metadata;
CREATE PROCEDURE simplify_background_image_metadata()
    MODIFIES SQL DATA
BEGIN ATOMIC
    DECLARE tbl_count INT DEFAULT 0;
    SELECT COUNT(*) INTO tbl_count
    FROM   information_schema.tables
    WHERE  table_name = 'BACKGROUND_IMAGE_METADATA';
    IF tbl_count > 0 THEN
        ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS original_filename;
        ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS content_type;
        ALTER TABLE background_image_metadata DROP COLUMN IF EXISTS file_size;
    END IF;
END;
CALL simplify_background_image_metadata();
DROP PROCEDURE IF EXISTS simplify_background_image_metadata;

