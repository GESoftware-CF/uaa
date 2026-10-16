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
import java.io.InputStream;
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Business logic for background image upload and deletion.
 *
 * <p>Uploads to a unique S3 key
 * ({@code fss-iam/uaa/background_image/{zoneId}/background-image-{timestamp}-{random}.{ext}})
 * and persists the CloudFront URL together with audit metadata ({@code uploadedAt},
 * {@code uploadedBy}) in {@code identity_zone.config.branding}. Each upload creates a new
 * object, so the previous image is removed after the new one is saved.
 */
@Service
@ConditionalOnProperty(name = {"AWS_REGION", "BACKGROUND_IMAGE_STORAGE_BUCKET",
        "BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES", "BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN"})
public class BackgroundImageService implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private static final String KEY_PREFIX = "fss-iam/uaa/background_image/";
    private static final String OBJECT_NAME = "background-image";
    private static final int MAX_UPLOAD_ATTEMPTS = 3;
    private static final long RETRY_BACKOFF_MS = 500;

    /** Permitted MIME types mapped to the file extension used in the S3 key. */
    private static final Map<String, String> ALLOWED_TYPES_TO_EXTENSION = Map.of(
            "image/png", "png",
            "image/jpeg", "jpg");

    private final S3StorageManager s3StorageManager;
    private final IdentityZoneProvisioning zoneProvisioning;
    private final String bucket;
    private final long minFileSizeBytes;
    private final long maxFileSizeBytes;
    private final String cloudFrontDomain;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  IdentityZoneProvisioning zoneProvisioning,
                                  @Value("${BACKGROUND_IMAGE_STORAGE_BUCKET}") String bucket,
                                  @Value("${BACKGROUND_IMAGE_UPLOAD_MIN_SIZE_BYTES:1}") long minFileSizeBytes,
                                  @Value("${BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES}") long maxFileSizeBytes,
                                  @Value("${BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN}") String cloudFrontDomain) {
        if (minFileSizeBytes <= 0 || minFileSizeBytes > maxFileSizeBytes) {
            throw new IllegalArgumentException(
                    "BACKGROUND_IMAGE_UPLOAD_MIN_SIZE_BYTES must be > 0 and <= BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES");
        }
        this.s3StorageManager = s3StorageManager;
        this.zoneProvisioning = zoneProvisioning;
        this.bucket = bucket;
        this.minFileSizeBytes = minFileSizeBytes;
        this.maxFileSizeBytes = maxFileSizeBytes;
        this.cloudFrontDomain = cloudFrontDomain;
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    public void uploadBackgroundImage(MultipartFile file, String zoneId) {
        long size = file.getSize();
        if (size > maxFileSizeBytes) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE,
                    "Image exceeds maximum allowed size of " + maxFileSizeBytes + " bytes");
        }
        if (size < minFileSizeBytes) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Image must be at least " + minFileSizeBytes + " bytes");
        }
        String contentType = resolveContentType(file);
        if (!ALLOWED_TYPES_TO_EXTENSION.containsKey(contentType)) {
            throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported image type '" + contentType + "'. Allowed: " + ALLOWED_TYPES_TO_EXTENSION.keySet());
        }

        Instant now = Instant.now();
        String s3Key = buildS3Key(zoneId, contentType, now.toEpochMilli());

        logger.info("Uploading background image: bucket={}, key={}, contentType={}", bucket, s3Key, contentType);
        uploadWithRetry(file, s3Key, contentType);

        String url = "https://" + cloudFrontDomain + "/" + s3Key;
        String previousUrl;
        try {
            IdentityZone zone = zoneProvisioning.retrieve(zoneId);
            IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
            BrandingInformation branding = config.getBranding() != null ? config.getBranding() : new BrandingInformation();
            previousUrl = branding.getBackgroundImageUrl();
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

        deletePreviousImageQuietly(previousUrl, s3Key, zoneId);
    }

    /**
     * Uploads to S3, making up to {@link #MAX_UPLOAD_ATTEMPTS} attempts.
     * A fresh input stream is opened for each attempt because a consumed stream cannot be re-read.
     */
    private void uploadWithRetry(MultipartFile file, String s3Key, String contentType) {
        for (int attempt = 1; ; attempt++) {
            try (InputStream in = file.getInputStream()) {
                s3StorageManager.upload(bucket, s3Key, in, file.getSize(), contentType);
                return;
            } catch (IOException | RuntimeException e) {
                if (attempt >= MAX_UPLOAD_ATTEMPTS) {
                    logger.error("S3 upload failed after {} attempts: key={}", attempt, s3Key, e);
                    throw new RuntimeException("Failed to upload image to S3 after " + attempt + " attempts", e);
                }
                logger.warn("S3 upload attempt {}/{} failed for key={}; retrying", attempt, MAX_UPLOAD_ATTEMPTS, s3Key, e);
                backoff(attempt);
            }
        }
    }

    private static void backoff(int attempt) {
        try {
            Thread.sleep(RETRY_BACKOFF_MS * attempt);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Upload interrupted while waiting to retry", ie);
        }
    }

    /** Removes the replaced image. Never fails the request, since the new image is already live. */
    private void deletePreviousImageQuietly(String previousUrl, String newKey, String zoneId) {
        if (previousUrl == null || previousUrl.isBlank()) {
            return;
        }
        try {
            extractManagedKey(previousUrl, zoneId)
                    .filter(previousKey -> !previousKey.equals(newKey))
                    .ifPresent(previousKey -> s3StorageManager.delete(bucket, previousKey));
        } catch (RuntimeException e) {
            logger.warn("Previous background image cleanup failed for zone={}, url={}", zoneId, previousUrl, e);
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    /**
     * Deletes the zone's background image from S3 and clears upload metadata from the zone config.
     *
     * @return {@code true} if an image was removed, {@code false} if the zone had none
     */
    public boolean deleteBackgroundImage(String zoneId) {
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        IdentityZoneConfiguration config = zone.getConfig();
        BrandingInformation branding = config != null ? config.getBranding() : null;
        if (branding == null || branding.getBackgroundImageUrl() == null || branding.getBackgroundImageUrl().isBlank()) {
            logger.info("Delete requested but no background image in zone config: zoneId={}", zoneId);
            return false;
        }

        // The key is derived from the stored URL, because keys are unique per upload.
        Optional<String> s3Key = extractManagedKey(branding.getBackgroundImageUrl(), zoneId);
        if (s3Key.isPresent()) {
            logger.info("Deleting background image for zone={}, key={}", zoneId, s3Key.get());
            s3StorageManager.delete(bucket, s3Key.get());
            logger.info("S3 object deleted: bucket={}, key={}", bucket, s3Key.get());
        } else {
            logger.warn("Stored URL is not a managed image URL for this zone; skipping S3 delete. zone={}", zoneId);
        }

        branding.setBackgroundImageUrl(null);
        branding.setBackgroundImageUploadedAt(null);
        branding.setBackgroundImageUploadedBy(null);
        config.setBranding(branding);
        zone.setConfig(config);
        try {
            zoneProvisioning.update(zone);
        } catch (Exception e) {
            logger.error("S3 delete succeeded but DB update failed for zone={}; DB metadata may be stale. key={}",
                    zoneId, s3Key.orElse(null), e);
            throw new RuntimeException("Background image deleted from S3 but failed to clear URL in zone config", e);
        }
        logger.info("Cleared background image metadata from zone config: zoneId={}", zoneId);
        return true;
    }

    // -------------------------------------------------------------------------
    // BackgroundImageUrlProvider
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the S3 key for a URL on our CloudFront domain, but only if the key belongs to the
     * given zone. Returns empty for any other URL, so a tampered DB value cannot cause deletion
     * of an unrelated object.
     */
    private Optional<String> extractManagedKey(String url, String zoneId) {
        try {
            URI uri = URI.create(url);
            String path = uri.getPath();
            if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(cloudFrontDomain)
                    || path == null || path.length() < 2 || path.contains("..")) {
                return Optional.empty();
            }
            String key = path.substring(1);
            boolean currentFormat = key.startsWith(KEY_PREFIX + zoneId + "/");
            boolean legacyFormat = key.startsWith("fss-iam/uaa/" + zoneId + "/background_image/");
            return (currentFormat || legacyFormat) ? Optional.of(key) : Optional.empty();
        } catch (IllegalArgumentException e) {
            logger.warn("Malformed background image URL: {}", url);
            return Optional.empty();
        }
    }

    private static String buildS3Key(String zoneId, String contentType, long timestampMillis) {
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        return KEY_PREFIX + zoneId + "/" + OBJECT_NAME + "-" + timestampMillis + "-" + randomSuffix
                + "." + ALLOWED_TYPES_TO_EXTENSION.get(contentType);
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

    private static String resolveContentType(MultipartFile file) {
        String raw = file.getContentType();
        if (raw == null || raw.isBlank()) {
            return "application/octet-stream";
        }
        return raw.split(";")[0].trim();
    }
}