package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/**
 * Business logic for background image upload and deletion.
 *
 * <p>Upload flow:
 * <ol>
 *   <li>Derive S3 key: {@code uaa/background-images/{zoneId}/{uuid}_{filename}}</li>
 *   <li>Upload bytes to S3 via {@link S3StorageManager#upload}</li>
 *   <li>Build the public S3 URL and store it in
 *       {@code identity_zone.config.branding.backgroundImageUrl}</li>
 * </ol>
 *
 * <p>The login page reads the URL directly from the zone config — no GET API needed.
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private final S3StorageManager s3StorageManager;
    private final IdentityZoneProvisioning zoneProvisioning;
    private final String bucket;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  IdentityZoneProvisioning zoneProvisioning,
                                  @Value("${background-image.storage.bucket}") String bucket) {
        this.s3StorageManager = s3StorageManager;
        this.zoneProvisioning = zoneProvisioning;
        this.bucket = bucket;
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    /**
     * Upload a background image for the given zone to S3 and persist the public
     * S3 URL in the identity zone's config JSON.
     *
     * <p>S3 key format: {@code uaa/background-images/{zoneId}/{uuid}_{originalFilename}}
     *
     * @param file   multipart image file supplied by the caller
     * @param zoneId identity zone this image belongs to
     * @throws RuntimeException if the S3 upload fails or the file cannot be read
     */
    public void uploadBackgroundImage(MultipartFile file, String zoneId) {
        String contentType = resolveContentType(file);
        String originalFilename = file.getOriginalFilename() != null
                ? file.getOriginalFilename() : "image";

        // Delete the existing S3 object (if any) before uploading the new one
        // so that only one image per zone exists in the bucket.
        deleteExistingS3Image(zoneId);

        String s3Key = buildKey(zoneId, originalFilename);

        logger.info("Uploading background image: bucket={}, key={}", bucket, s3Key);

        try {
            s3StorageManager.upload(bucket, s3Key, file.getInputStream(), file.getSize(), contentType);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read uploaded image file", e);
        }

        // Build public S3 URL and store in zone config
        String publicUrl = s3StorageManager.getDirectUrl(bucket, s3Key);
        updateZoneBackgroundImageUrl(zoneId, publicUrl);

        logger.info("Successfully uploaded to S3: {}, URL stored in zone config", publicUrl);
    }

    /**
     * Delete the existing S3 image for the given zone (best-effort).
     * Extracts the S3 key from the currently stored URL in the zone config.
     */
    private void deleteExistingS3Image(String zoneId) {
        try {
            IdentityZone zone = zoneProvisioning.retrieve(zoneId);
            IdentityZoneConfiguration config = zone.getConfig();
            if (config == null || config.getBranding() == null) {
                return;
            }
            String currentUrl = config.getBranding().getBackgroundImageUrl();
            if (currentUrl == null || currentUrl.isBlank()) {
                return;
            }
            String expectedPrefix = s3StorageManager.getDirectUrl(bucket, "");
            if (currentUrl.startsWith(expectedPrefix)) {
                String s3Key = currentUrl.substring(expectedPrefix.length());
                s3StorageManager.delete(bucket, s3Key);
                logger.info("Deleted previous S3 image before re-upload: bucket={}, key={}", bucket, s3Key);
            }
        } catch (Exception e) {
            logger.warn("Could not delete previous S3 image for zone={}: {}", zoneId, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    /**
     * Delete the active background image for the given zone.
     *
     * <p>Clears {@code config.branding.backgroundImageUrl} from the zone config.
     * The S3 object is also deleted (best-effort).
     *
     * @param zoneId the identity zone ID
     * @return {@code true} if an image URL was present and cleared, {@code false} otherwise
     */
    public boolean deleteBackgroundImage(String zoneId) {
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig();
        if (config == null || config.getBranding() == null
                || config.getBranding().getBackgroundImageUrl() == null) {
            logger.info("Delete requested but no background image URL in zone config: zoneId={}", zoneId);
            return false;
        }

        String currentUrl = config.getBranding().getBackgroundImageUrl();
        logger.info("Deleting background image for zone={}, url={}", zoneId, currentUrl);

        // Try to extract the S3 key from the URL and delete the object
        try {
            String expectedPrefix = s3StorageManager.getDirectUrl(bucket, "");
            if (currentUrl.startsWith(expectedPrefix)) {
                String s3Key = currentUrl.substring(expectedPrefix.length());
                s3StorageManager.delete(bucket, s3Key);
                logger.info("Deleted S3 object: bucket={}, key={}", bucket, s3Key);
            }
        } catch (Exception e) {
            logger.warn("Failed to delete S3 object for zone={}: {}", zoneId, e.getMessage());
        }

        // Clear the URL from zone config
        config.getBranding().setBackgroundImageUrl(null);
        zone.setConfig(config);
        zoneProvisioning.update(zone);
        logger.info("Cleared backgroundImageUrl from zone config: zoneId={}", zoneId);

        return true;
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    /**
     * Update the identity zone config to store the background image URL and upload audit metadata.
     */
    private void updateZoneBackgroundImageUrl(String zoneId, String publicUrl) {
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig();
        if (config == null) {
            config = new IdentityZoneConfiguration();
        }
        BrandingInformation branding = config.getBranding();
        if (branding == null) {
            branding = new BrandingInformation();
            config.setBranding(branding);
        }
        branding.setBackgroundImageUrl(publicUrl);
        branding.setBackgroundImageUploadedAt(Instant.now().toString());
        branding.setBackgroundImageUploadedBy(resolveUploader());
        zone.setConfig(config);
        zoneProvisioning.update(zone);
        logger.info("Zone config updated with backgroundImageUrl: zoneId={}, url={}", zoneId, publicUrl);
    }

    /**
     * Resolve the identity of the caller from the Spring Security context.
     * Returns the client_id / username, or "unknown" if unavailable.
     */
    private static String resolveUploader() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) {
                return auth.getName();
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return "unknown";
    }

    /**
     * Build the S3 key for the background image.
     * Format: {@code uaa/background-images/{zoneId}/{uuid}_{filename}}
     */
    private String buildKey(String zoneId, String originalFilename) {
        return "uaa/background-images/" + zoneId + "/" + UUID.randomUUID() + "_" + originalFilename;
    }

    /**
     * Extract the bare MIME type from the file's content-type header.
     */
    private static String resolveContentType(MultipartFile file) {
        String raw = file.getContentType();
        if (raw == null || raw.isBlank()) {
            return "application/octet-stream";
        }
        return raw.split(";")[0].trim();
    }
}
