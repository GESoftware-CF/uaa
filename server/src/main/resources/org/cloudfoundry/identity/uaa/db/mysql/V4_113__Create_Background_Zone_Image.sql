-- Flyway migration: create background_zone_image table (MySQL)
--
-- Operational mapping: one row per identity zone pointing to that zone's
-- currently active background image in S3. No audit history — upserted on
-- upload, deleted when the image is removed.
CREATE TABLE IF NOT EXISTS background_zone_image (
    zone_id VARCHAR(36)  NOT NULL,
    s3_key  VARCHAR(512) NOT NULL,
    CONSTRAINT pk_background_zone_image PRIMARY KEY (zone_id)
);

