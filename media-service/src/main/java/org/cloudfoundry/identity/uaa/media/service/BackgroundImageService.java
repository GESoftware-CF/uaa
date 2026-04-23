package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.media.exception.BackgroundImageConflictException;
import org.cloudfoundry.identity.uaa.media.exception.BackgroundImageNotFoundException;
import org.cloudfoundry.identity.uaa.media.exception.BackgroundImageUploadException;
import org.cloudfoundry.identity.uaa.media.model.BackgroundImage;
import org.cloudfoundry.identity.uaa.media.provisioning.BackgroundImageProvisioning;
import org.cloudfoundry.identity.uaa.media.validation.BackgroundImageValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * Service for managing background image lifecycle: upload, retrieve, delete.
 * Orchestrates validation, S3 storage, database persistence, and audit logging.
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private final BackgroundImageProvisioning provisioning;
    private final S3StorageManager s3StorageManager;
    private final BackgroundImageValidator validator;
    private final LoggingAuditService auditService;
    private final String storageBucket;
    private final String keyPrefix;

    public BackgroundImageService(
            BackgroundImageProvisioning provisioning,
            S3StorageManager s3StorageManager,
            BackgroundImageValidator validator,
            LoggingAuditService auditService,
            @Value("${background-image.storage.bucket}") String storageBucket,
            @Value("${background-image.storage.key-prefix:media}") String keyPrefix) {
        this.provisioning = provisioning;
        this.s3StorageManager = s3StorageManager;
        this.validator = validator;
        this.auditService = auditService;
        this.storageBucket = storageBucket;
        this.keyPrefix = keyPrefix;
    }

    /**
     * Upload a background image for a zone.
     * Phase 1: Enforces one-image-per-zone via conflict check.
     *
     * @param file uploaded image file
     * @param identityZoneId zone ID
     * @param uploadedBy user ID who performed the upload
     * @return created BackgroundImage entity
     * @throws BackgroundImageConflictException if zone already has a background
     * @throws BackgroundImageUploadException if upload or persistence fails
     */
    @Transactional
    public BackgroundImage uploadBackgroundImage(MultipartFile file, String identityZoneId, String uploadedBy) {
        try {
            logger.info("Starting background image upload: zone={}, uploader={}, filename={}, size={}",
                identityZoneId, uploadedBy, file.getOriginalFilename(), file.getSize());

            // Phase 1: Enforce one-per-zone (will be replaced with soft-delete + update in Phase 2)
            if (provisioning.existsByZoneId(identityZoneId)) {
                throw new BackgroundImageConflictException(identityZoneId);
            }

            // Validate file (MIME type + size)
            String detectedMimeType = validator.validate(file);
            String sanitizedFilename = validator.sanitizeFilename(file.getOriginalFilename());
            
            // Build S3 key: media/zone/{zoneId}/background/{uuid}/{filename}
            String objectId = java.util.UUID.randomUUID().toString();
            String s3Key = String.format("%s/zone/%s/background/%s/%s",
                keyPrefix, identityZoneId, objectId, sanitizedFilename);

            // Upload to S3 (streaming, multipart for large files)
            s3StorageManager.upload(
                storageBucket,
                s3Key,
                file.getInputStream(),
                file.getSize(),
                detectedMimeType
            );

            // Create database record
            BackgroundImage backgroundImage = new BackgroundImage();
            backgroundImage.setIdentityZoneId(identityZoneId);
            backgroundImage.setUploadedBy(uploadedBy);
            backgroundImage.setOriginalFilename(sanitizedFilename);
            backgroundImage.setStorageBucket(storageBucket);
            backgroundImage.setStorageKey(s3Key);
            backgroundImage.setMimeType(detectedMimeType);
            backgroundImage.setSizeBytes(file.getSize());

            BackgroundImage created = provisioning.create(backgroundImage);

            // Emit audit log (async, non-blocking)
            logAudit(uploadedBy, identityZoneId, "BackgroundImageUpload",
                String.format("Uploaded background image: %s (%d bytes)", sanitizedFilename, file.getSize()));

            logger.info("Successfully uploaded background image: id={}, zone={}, key={}",
                created.getId(), identityZoneId, s3Key);

            return created;

        } catch (IOException e) {
            logger.error("Failed to read uploaded file: zone={}", identityZoneId, e);
            throw new BackgroundImageUploadException("Failed to read uploaded file", e);
        } catch (BackgroundImageConflictException | BackgroundImageUploadException e) {
            throw e; // Re-throw known exceptions
        } catch (Exception e) {
            logger.error("Unexpected error during background image upload: zone={}", identityZoneId, e);
            throw new BackgroundImageUploadException("Background image upload failed", e);
        }
    }

    /**
     * Retrieve the active background image for a zone.
     *
     * @param identityZoneId zone ID
     * @return BackgroundImage entity
     * @throws BackgroundImageNotFoundException if no active image exists
     */
    public BackgroundImage getBackgroundImage(String identityZoneId) {
        BackgroundImage image = provisioning.retrieveByZoneId(identityZoneId);
        if (image == null) {
            throw new BackgroundImageNotFoundException(identityZoneId, "No background image found");
        }
        return image;
    }

    /**
     * Download the background image bytes from S3.
     *
     * @param identityZoneId zone ID
     * @return image bytes, MIME type, and filename
     * @throws BackgroundImageNotFoundException if no active image exists
     */
    public ImageDownloadResult downloadBackgroundImage(String identityZoneId) {
        BackgroundImage image = getBackgroundImage(identityZoneId);
        
        byte[] imageBytes = s3StorageManager.download(image.getStorageBucket(), image.getStorageKey());
        
        return new ImageDownloadResult(imageBytes, image.getMimeType(), image.getOriginalFilename());
    }

    /**
     * Soft-delete a background image.
     *
     * @param identityZoneId zone ID
     * @param deletedBy user ID who performed the delete
     */
    @Transactional
    public void deleteBackgroundImage(String identityZoneId, String deletedBy) {
        BackgroundImage image = getBackgroundImage(identityZoneId);
        
        // Soft-delete in DB
        provisioning.delete(image.getId());
        
        // Delete from S3 (non-blocking, failures logged only)
        s3StorageManager.delete(image.getStorageBucket(), image.getStorageKey());
        
        // Emit audit log
        logAudit(deletedBy, identityZoneId, "BackgroundImageDelete",
            String.format("Deleted background image: %s", image.getOriginalFilename()));
        
        logger.info("Successfully deleted background image: id={}, zone={}", image.getId(), identityZoneId);
    }

    /**
     * Emit audit log (non-blocking, failure only logged as warning)
     */
    private void logAudit(String principal, String identityZoneId, String type, String description) {
        try {
            AuditEvent event = new AuditEvent(
                principal,
                AuditEventType.valueOf(type),
                String.format("identity_zone_id=%s, %s", identityZoneId, description),
                System.currentTimeMillis()
            );
            auditService.log(event);
        } catch (Exception e) {
            logger.warn("Failed to emit audit log: type={}, zone={}", type, identityZoneId, e);
        }
    }

    /**
     * DTO for download results
     */
    public static class ImageDownloadResult {
        private final byte[] imageBytes;
        private final String mimeType;
        private final String filename;

        public ImageDownloadResult(byte[] imageBytes, String mimeType, String filename) {
            this.imageBytes = imageBytes;
            this.mimeType = mimeType;
            this.filename = filename;
        }

        public byte[] getImageBytes() {
            return imageBytes;
        }

        public String getMimeType() {
            return mimeType;
        }

        public String getFilename() {
            return filename;
        }
    }
}
