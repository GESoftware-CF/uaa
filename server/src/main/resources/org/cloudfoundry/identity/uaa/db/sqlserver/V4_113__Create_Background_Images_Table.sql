-- Create background_images table for storing tenant background image metadata
CREATE TABLE background_images (
    id                   VARCHAR(36) NOT NULL PRIMARY KEY,
    identity_zone_id     VARCHAR(36) NOT NULL,
    uploaded_by          VARCHAR(36) NOT NULL,
    original_filename    VARCHAR(255),
    storage_bucket       VARCHAR(255) NOT NULL,
    storage_key          VARCHAR(512) NOT NULL,
    mime_type            VARCHAR(100) NOT NULL,
    size_bytes           BIGINT NOT NULL,
    created              DATETIME NOT NULL DEFAULT GETDATE(),
    last_modified        DATETIME NOT NULL DEFAULT GETDATE(),
    deleted_at           DATETIME NULL
);

-- Index for zone-scoped queries (active images only)
CREATE INDEX background_images_zone_idx 
    ON background_images (identity_zone_id, deleted_at);
