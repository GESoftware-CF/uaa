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

/**
 * Business logic for background image upload and deletion.
 *
 * <p>Uploads to a fixed S3 key ({@code uaa/{zoneId}/background-image}); persists only the
 * upload timestamp in the zone config as a cache-busting token — the URL is computed at
 * read time so it cannot be erased by a concurrent {@code PUT /identity-zones/{id}}.
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    /** Fixed object name inside each zone's S3 folder. */
    private static final String BACKGROUND_IMAGE_OBJECT_NAME = "background-image";

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

    public void uploadBackgroundImage(MultipartFile file, String zoneId) {
        String s3Key = buildFixedKey(zoneId);
        logger.info("Uploading background image: bucket={}, key={}", bucket, s3Key);
        try {
            s3StorageManager.upload(bucket, s3Key, file.getInputStream(), file.getSize(), resolveContentType(file));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read uploaded image file", e);
        }
        Instant now = Instant.now();
        String url = s3StorageManager.getDirectUrl(bucket, s3Key) + "?v=" + now.toEpochMilli();
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        BrandingInformation branding = config.getBranding() != null ? config.getBranding() : new BrandingInformation();
        branding.setBackgroundImageUrl(url);
        branding.setBackgroundImageUploadedAt(now.toString());
        branding.setBackgroundImageUploadedBy(resolveUploader());
        config.setBranding(branding);
        zone.setConfig(config);
        zoneProvisioning.update(zone);
        logger.info("Uploaded to S3 and stored URL in zone config: {}", url);
    }

    /**
     * Deletes the zone's background image from S3 and clears upload metadata from the zone config.
     */
    public boolean deleteBackgroundImage(String zoneId) {
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig();
        if (config == null || config.getBranding() == null
                || config.getBranding().getBackgroundImageUrl() == null) {
            logger.info("Delete requested but no background image in zone config: zoneId={}", zoneId);
            return false;
        }

        String s3Key = buildFixedKey(zoneId);
        logger.info("Deleting background image for zone={}, key={}", zoneId, s3Key);

        try {
            s3StorageManager.delete(bucket, s3Key);
            logger.info("Deleted S3 object: bucket={}, key={}", bucket, s3Key);
        } catch (Exception e) {
            logger.warn("Failed to delete S3 object for zone={}: {}", zoneId, e.getMessage());
        }

        config.getBranding().setBackgroundImageUrl(null);
        config.getBranding().setBackgroundImageUploadedAt(null);
        config.getBranding().setBackgroundImageUploadedBy(null);
        zone.setConfig(config);
        zoneProvisioning.update(zone);
        logger.info("Cleared background image metadata from zone config: zoneId={}", zoneId);
        return true;
    }

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

    private static String buildFixedKey(String zoneId) {
        return "uaa/" + zoneId + "/" + BACKGROUND_IMAGE_OBJECT_NAME;
    }

    private static String resolveContentType(MultipartFile file) {
        String raw = file.getContentType();
        if (raw == null || raw.isBlank()) {
            return "application/octet-stream";
        }
        return raw.split(";")[0].trim();
    }
}
