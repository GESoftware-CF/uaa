package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.login.BackgroundImageUrlProvider;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/**
 * Business logic for background image upload and deletion.
 *
 * <p>Uploads to a fixed S3 key ({@code uaa/{zoneId}/background-image}) and persists the
 * public URL together with audit metadata ({@code uploadedAt}, {@code uploadedBy}) in
 * {@code identity_zone.config.branding}. The URL includes a {@code ?v=} cache-buster
 * timestamp updated on every upload.
 */
@Service
@ConditionalOnProperty(name = {"AWS_REGION", "BACKGROUND_IMAGE_STORAGE_BUCKET", "BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES"})
public class BackgroundImageService implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    /** Fixed object name inside each zone's S3 folder. */
    private static final String BACKGROUND_IMAGE_OBJECT_NAME = "background-image";

    /** Permitted MIME types for zone background images. */
    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of("image/png", "image/jpeg", "image/webp");

    private final S3StorageManager s3StorageManager;
    private final IdentityZoneProvisioning zoneProvisioning;
    private final String bucket;
    private final long maxFileSizeBytes;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  IdentityZoneProvisioning zoneProvisioning,
                                  @Value("${BACKGROUND_IMAGE_STORAGE_BUCKET}") String bucket,
                                  @Value("${BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES}") long maxFileSizeBytes) {
        this.s3StorageManager = s3StorageManager;
        this.zoneProvisioning = zoneProvisioning;
        this.bucket = bucket;
        this.maxFileSizeBytes = maxFileSizeBytes;
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    public void uploadBackgroundImage(MultipartFile file, String zoneId) {
        if (file.getSize() > maxFileSizeBytes) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "Image exceeds maximum allowed size of " + maxFileSizeBytes + " bytes");
        }
        String contentType = resolveContentType(file);
        if (!ALLOWED_CONTENT_TYPES.contains(contentType)) {
            throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported image type '" + contentType + "'. Allowed: " + ALLOWED_CONTENT_TYPES);
        }
        String s3Key = buildFixedKey(zoneId);
        logger.info("Uploading background image: bucket={}, key={}, contentType={}", bucket, s3Key, contentType);
        try {
            s3StorageManager.upload(bucket, s3Key, file.getInputStream(), file.getSize(), contentType);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read uploaded image file", e);
        }
        Instant now = Instant.now();
        String url = s3StorageManager.getDirectUrl(bucket, s3Key) + "?v=" + now.toEpochMilli();
        try {
            IdentityZone zone = zoneProvisioning.retrieve(zoneId);
            IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
            BrandingInformation branding = config.getBranding() != null ? config.getBranding() : new BrandingInformation();
            branding.setBackgroundImageUrl(url);
            branding.setBackgroundImageUploadedAt(now.toString());
            branding.setBackgroundImageUploadedBy(resolveUploader());
            config.setBranding(branding);
            zone.setConfig(config);
            zoneProvisioning.update(zone);
        } catch (Exception e) {
            logger.error("S3 upload succeeded but DB update failed for zone={}; S3 key={} may be orphaned. URL={}",
                    zoneId, s3Key, url, e);
            throw new RuntimeException("Image uploaded to S3 but failed to persist URL in zone config", e);
        }
        logger.info("Uploaded to S3 and stored URL in zone config: {}", url);
    }

    /**
     * Deletes the zone's background image from S3 and clears upload metadata from the zone config.
     */
    public boolean deleteBackgroundImage(String zoneId) {
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig();
        BrandingInformation branding = config != null ? config.getBranding() : null;
        if (branding == null || branding.getBackgroundImageUrl() == null) {
            logger.info("Delete requested but no background image in zone config: zoneId={}", zoneId);
            return false;
        }

        String s3Key = buildFixedKey(zoneId);
        logger.info("Deleting background image for zone={}, key={}", zoneId, s3Key);
        s3StorageManager.delete(bucket, s3Key);
        logger.info("S3 object deleted: bucket={}, key={}", bucket, s3Key);

        branding.setBackgroundImageUrl(null);
        branding.setBackgroundImageUploadedAt(null);
        branding.setBackgroundImageUploadedBy(null);
        config.setBranding(branding);
        zone.setConfig(config);
        try {
            zoneProvisioning.update(zone);
        } catch (Exception e) {
            logger.error("S3 delete succeeded but DB update failed for zone={}; DB metadata may be stale. key={}",
                    zoneId, s3Key, e);
            throw new RuntimeException("Background image deleted from S3 but failed to clear URL in zone config", e);
        }
        logger.info("Cleared background image metadata from zone config: zoneId={}", zoneId);
        return true;
    }

    // -------------------------------------------------------------------------
    // BackgroundImageUrlProvider
    // -------------------------------------------------------------------------

    /**
     * Resolves the background image URL for the currently active identity zone from
     * {@code identity_zone.config.branding.backgroundImageUrl}.
     *
     * @return the configured URL, or {@link Optional#empty()} when none is set
     */
    @Override
    public Optional<String> getBackgroundImageUrl() {
        try {
            return Optional.ofNullable(IdentityZoneHolder.get().getConfig())
                    .map(IdentityZoneConfiguration::getBranding)
                    .map(BrandingInformation::getBackgroundImageUrl)
                    .filter(url -> !url.isBlank());
        } catch (Exception e) {
            logger.warn("Failed to resolve background image URL; falling back to default", e);
            return Optional.empty();
        }
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
