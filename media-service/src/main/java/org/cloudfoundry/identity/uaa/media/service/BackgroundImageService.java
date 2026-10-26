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
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkServiceException;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;

/**
 * Business logic for background image upload and deletion.
 *
 * <p>Objects are stored in S3 at {@code {basePath}/{zoneId}/{timestamp}-{random}.{ext}}.
 * The database stores only the relative value {@code {zoneId}/{timestamp}-{random}.{ext}}
 * in {@code identity_zone.config.branding.backgroundImageUrl}, with audit metadata
 * ({@code uploadedAt}, {@code uploadedBy}). The full CloudFront URL is built from configuration
 * at read time. Zones without a valid image get {@code {basePath}/defaultimage.jpg}.
 *
 * <p>Uploads are retried up to {@link #MAX_UPLOAD_ATTEMPTS} times, but only for transient S3
 * failures (5xx, throttling, timeouts, network errors). Permanent failures such as 403 fail
 * immediately without retrying.
 */
@Service
@ConditionalOnProperty(name = {"AWS_REGION", "BACKGROUND_IMAGE_STORAGE_BUCKET",
        "BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES", "BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN",
        "BACKGROUND_IMAGE_BASE_PATH"})
public class BackgroundImageService implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    /** Fallback image at {basePath}/defaultimage.jpg, uploaded once per environment outside the app. */
    private static final String DEFAULT_IMAGE_NAME = "defaultimage.jpg";

    private static final int MAX_UPLOAD_ATTEMPTS = 3;
    private static final long RETRY_BASE_DELAY_MS = 300;

    /** e.g. int/iam/uaa/background_images (no leading or trailing slash). */
    private static final Pattern BASE_PATH_PATTERN =
            Pattern.compile("[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*");
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?");
    /** Any id of 1-255 safe characters, except "." and "..". */
    private static final Pattern ZONE_ID_PATTERN = Pattern.compile("(?!\\.{1,2}$)[a-zA-Z0-9._-]{1,255}");
    /** {timestamp}-{8 hex chars}.{ext} */
    private static final Pattern IMAGE_NAME_PATTERN = Pattern.compile("\\d{10,}-[0-9a-f]{8}\\.(png|jpg)");

    /** Permitted MIME types mapped to the file extension used in the image name. */
    private static final Map<String, String> ALLOWED_TYPES_TO_EXTENSION = Map.of(
            "image/png", "png",
            "image/jpeg", "jpg");

    private final S3StorageManager s3StorageManager;
    private final IdentityZoneProvisioning zoneProvisioning;
    private final String bucket;
    private final long minFileSizeBytes;
    private final long maxFileSizeBytes;
    /** {@code {basePath}/} */
    private final String keyPrefix;
    /** {@code https://{cloudFrontDomain}/{basePath}/} */
    private final String imageUrlPrefix;
    private final String defaultImageUrl;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  IdentityZoneProvisioning zoneProvisioning,
                                  @Value("${BACKGROUND_IMAGE_STORAGE_BUCKET}") String bucket,
                                  @Value("${BACKGROUND_IMAGE_UPLOAD_MIN_SIZE_BYTES:1}") long minFileSizeBytes,
                                  @Value("${BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES}") long maxFileSizeBytes,
                                  @Value("${BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN}") String cloudFrontDomain,
                                  @Value("${BACKGROUND_IMAGE_BASE_PATH}") String basePath) {
        if (minFileSizeBytes <= 0 || minFileSizeBytes > maxFileSizeBytes) {
            throw new IllegalArgumentException(
                    "BACKGROUND_IMAGE_UPLOAD_MIN_SIZE_BYTES must be > 0 and <= BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES");
        }
        if (cloudFrontDomain == null || !HOSTNAME_PATTERN.matcher(cloudFrontDomain).matches()) {
            throw new IllegalArgumentException(
                    "BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN must be a hostname without scheme, path or port");
        }
        if (basePath == null || !BASE_PATH_PATTERN.matcher(basePath).matches()) {
            throw new IllegalArgumentException(
                    "BACKGROUND_IMAGE_BASE_PATH must be a relative path without leading/trailing slash, "
                            + "e.g. 'int/iam/uaa/background_images'");
        }
        this.s3StorageManager = s3StorageManager;
        this.zoneProvisioning = zoneProvisioning;
        this.bucket = bucket;
        this.minFileSizeBytes = minFileSizeBytes;
        this.maxFileSizeBytes = maxFileSizeBytes;
        this.keyPrefix = basePath + "/";
        this.imageUrlPrefix = "https://" + cloudFrontDomain.toLowerCase(Locale.ROOT) + "/" + keyPrefix;
        this.defaultImageUrl = imageUrlPrefix + DEFAULT_IMAGE_NAME;
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    public void uploadBackgroundImage(MultipartFile file, String zoneId) {
        validateZoneId(zoneId);
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
        String extension = ALLOWED_TYPES_TO_EXTENSION.get(contentType);
        if (extension == null) {
            throw new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported image type '" + contentType + "'. Allowed: " + ALLOWED_TYPES_TO_EXTENSION.keySet());
        }

        Instant now = Instant.now();
        String storedValue = zoneId + "/" + now.toEpochMilli() + "-"
                + UUID.randomUUID().toString().substring(0, 8) + "." + extension;
        String s3Key = keyPrefix + storedValue;

        logger.info("Uploading background image: bucket={}, key={}, contentType={}", bucket, s3Key, contentType);
        uploadWithRetry(file, s3Key, contentType);

        String previousValue;
        try {
            IdentityZone zone = zoneProvisioning.retrieve(zoneId);
            IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
            BrandingInformation branding = config.getBranding() != null ? config.getBranding() : new BrandingInformation();
            previousValue = branding.getBackgroundImageUrl();
            branding.setBackgroundImageUrl(storedValue);
            branding.setBackgroundImageUploadedAt(now.toString());
            branding.setBackgroundImageUploadedBy(resolveUploader());
            config.setBranding(branding);
            zone.setConfig(config);
            zoneProvisioning.update(zone);
        } catch (RuntimeException e) {
            logger.error("DB update failed for zone={}; removing uploaded object key={}", zoneId, s3Key, e);
            deleteQuietly(s3Key);
            throw e;
        }
        logger.info("Stored image reference in zone config: zone={}, value={}", zoneId, storedValue);

        // The new image is already live; cleanup of the replaced one must never fail the request.
        resolveManagedKey(previousValue, zoneId)
                .filter(previousKey -> !previousKey.equals(s3Key))
                .ifPresent(this::deleteQuietly);
    }

    /**
     * Uploads to S3, retrying up to {@link #MAX_UPLOAD_ATTEMPTS} times, but only for transient
     * failures (5xx, throttling, timeouts, network errors). Permanent failures such as 403 fail
     * immediately. A fresh input stream is opened for each attempt because a consumed stream
     * cannot be re-read.
     */
    private void uploadWithRetry(MultipartFile file, String s3Key, String contentType) {
        for (int attempt = 1; ; attempt++) {
            try (InputStream in = file.getInputStream()) {
                s3StorageManager.upload(bucket, s3Key, in, file.getSize(), contentType);
                return;
            } catch (IOException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unable to read uploaded image", e);
            } catch (RuntimeException e) {
                boolean transientFailure = isTransient(e);
                if (!transientFailure || attempt >= MAX_UPLOAD_ATTEMPTS) {
                    logger.error("S3 upload failed: key={}, attempt={}/{}, transient={}",
                            s3Key, attempt, MAX_UPLOAD_ATTEMPTS, transientFailure, e);
                    throw new ResponseStatusException(
                            transientFailure ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.BAD_GATEWAY,
                            "Image storage is currently unavailable", e);
                }
                logger.warn("S3 upload attempt {}/{} failed for key={}; retrying",
                        attempt, MAX_UPLOAD_ATTEMPTS, s3Key, e);
                sleepBeforeRetry(attempt);
            }
        }
    }

    /** Walks the cause chain because the storage manager wraps the SDK exception in a RuntimeException. */
    private static boolean isTransient(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SdkServiceException service) {
                int status = service.statusCode();
                return status >= 500 || status == 429 || status == 408;
            }
            if (t instanceof SdkClientException) {
                return true; // timeouts, connection resets
            }
        }
        return false; // unknown errors are not retried
    }

    private static void sleepBeforeRetry(int attempt) {
        long delay = RETRY_BASE_DELAY_MS * (1L << (attempt - 1)) + ThreadLocalRandom.current().nextLong(100);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Upload interrupted", ie);
        }
    }

    /** Removes the replaced image. Never fails the request, since the new image is already live. */
    private void deleteQuietly(String s3Key) {
        try {
            s3StorageManager.delete(bucket, s3Key);
        } catch (RuntimeException e) {
            logger.warn("Could not delete S3 object key={}; it may be orphaned", s3Key, e);
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    /**
     * Clears the zone's image reference, then removes the object from S3 (best-effort).
     * The database is the source of truth, so the login page never points to a deleted object.
     *
     * @return {@code true} if an image was removed, {@code false} if the zone had none
     */
    public boolean deleteBackgroundImage(String zoneId) {
        validateZoneId(zoneId);
        IdentityZone zone = zoneProvisioning.retrieve(zoneId);
        Optional<String> stored = storedReference(zone);
        if (stored.isEmpty()) {
            logger.info("Delete requested but no background image in zone config: zoneId={}", zoneId);
            return false;
        }

        BrandingInformation branding = zone.getConfig().getBranding();
        branding.setBackgroundImageUrl(null);
        branding.setBackgroundImageUploadedAt(null);
        branding.setBackgroundImageUploadedBy(null);
        zoneProvisioning.update(zone);
        logger.info("Cleared background image reference from zone config: zoneId={}", zoneId);

        resolveManagedKey(stored.get(), zoneId).ifPresentOrElse(this::deleteQuietly,
                () -> logger.warn("Stored value is not a managed image reference; skipping S3 delete. zone={}", zoneId));
        return true;
    }

    // -------------------------------------------------------------------------
    // BackgroundImageUrlProvider
    // -------------------------------------------------------------------------

    /**
     * Returns the CloudFront URL for the current zone's image, or the shared default image when the
     * zone has no valid stored reference. Reads only the in-memory zone config; no S3 or extra DB call.
     */
    @Override
    public Optional<String> getBackgroundImageUrl() {
        try {
            IdentityZone zone = IdentityZoneHolder.get();
            Optional<String> stored = storedReference(zone);
            if (stored.isPresent()) {
                if (isValidStoredValue(stored.get(), zone.getId())) {
                    return Optional.of(imageUrlPrefix + stored.get());
                }
                logger.warn("Invalid background image reference for zone={}; using default image", zone.getId());
            }
        } catch (RuntimeException e) {
            logger.warn("Failed to resolve background image URL; using default image", e);
        }
        return Optional.of(defaultImageUrl);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static Optional<String> storedReference(IdentityZone zone) {
        return Optional.ofNullable(zone.getConfig())
                .map(IdentityZoneConfiguration::getBranding)
                .map(BrandingInformation::getBackgroundImageUrl)
                .filter(value -> !value.isBlank());
    }

    /**
     * Maps a stored value to its S3 key, only if it has the expected format and belongs to the zone.
     * A tampered value therefore cannot cause deletion of an unrelated object.
     */
    private Optional<String> resolveManagedKey(String stored, String zoneId) {
        return stored != null && isValidStoredValue(stored, zoneId)
                ? Optional.of(keyPrefix + stored)
                : Optional.empty();
    }

    private static boolean isValidStoredValue(String stored, String zoneId) {
        String prefix = zoneId + "/";
        return stored.startsWith(prefix) && IMAGE_NAME_PATTERN.matcher(stored.substring(prefix.length())).matches();
    }

    private static void validateZoneId(String zoneId) {
        if (zoneId == null || !ZONE_ID_PATTERN.matcher(zoneId).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid identity zone id");
        }
    }

    private static String resolveUploader() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getName() != null ? auth.getName() : "unknown";
    }

    private static String resolveContentType(MultipartFile file) {
        String raw = file.getContentType();
        return raw == null ? "" : raw.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }
}