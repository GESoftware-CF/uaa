package org.cloudfoundry.identity.uaa.media.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * Entity representing a tenant background image stored in S3.
 * Each identity zone can have at most one active background image.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BackgroundImage {
    
    /**
     * Unique identifier (UUID)
     */
    private String id;
    
    /**
     * Identity zone ID that owns this background image
     */
    private String identityZoneId;
    
    /**
     * User ID who uploaded the image
     */
    private String uploadedBy;
    
    /**
     * Original filename from the user's file system
     */
    private String originalFilename;
    
    /**
     * S3 bucket name where the image is stored
     */
    private String storageBucket;
    
    /**
     * S3 object key (path) within the bucket
     */
    private String storageKey;
    
    /**
     * MIME type detected via magic-byte analysis (e.g., "image/png")
     */
    private String mimeType;
    
    /**
     * File size in bytes
     */
    private long sizeBytes;
    
    /**
     * Timestamp when the image was first created
     */
    private Date created;
    
    /**
     * Timestamp when the image was last modified
     */
    private Date lastModified;
    
    /**
     * Soft-delete timestamp (null = active)
     */
    private Date deletedAt;
    
    /**
     * Check if this background image is active (not soft-deleted)
     */
    public boolean isActive() {
        return deletedAt == null;
    }
}
