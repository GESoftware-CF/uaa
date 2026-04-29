package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.media.model.ZoneBackgroundImage;
import org.cloudfoundry.identity.uaa.media.repository.ZoneBackgroundImageRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Business logic for background image upload, retrieval, and deletion.
 *
 * <p>Orchestrates between {@link S3StorageManager} (object storage) and
 * {@link ZoneBackgroundImageRepository} (active-key tracking in the database).
 *
 * <p>Upload flow:
 * <ol>
 *   <li>Derive a deterministic S3 key: {@code {keyPrefix}/{zoneId}/{uuid}.{ext}}</li>
 *   <li>Upload bytes to S3 via {@link S3StorageManager#upload}</li>
 *   <li>Persist the {@code zoneId → s3Key} mapping via
 *       {@link ZoneBackgroundImageRepository#save} — this is the DB write the
 *       caller relies on to retrieve the image later</li>
 * </ol>
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private final S3StorageManager              s3StorageManager;
    private final ZoneBackgroundImageRepository repository;
    private final String                        bucket;
    private final String                        keyPrefix;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  ZoneBackgroundImageRepository repository,
                                  @Value("${background-image.storage.bucket}") String bucket,
                                  @Value("${background-image.storage.key-prefix:media}") String keyPrefix) {
        this.s3StorageManager = s3StorageManager;
        this.repository       = repository;
        this.bucket           = bucket;
        this.keyPrefix        = keyPrefix;
    }

    // -------------------------------------------------------------------------
    // Replace (PATCH)
    // -------------------------------------------------------------------------

    /**
     * Replace the active background image for the given zone.
     *
     * <p>Flow:
     * <ol>
     *   <li>Resolve the current S3 key from the database (returns empty if none exists)</li>
     *   <li>Upload the new image to S3</li>
     *   <li>Upsert the new {@code zoneId → s3Key} mapping in the database</li>
     *   <li>Delete the old S3 object (best-effort — logged but not re-thrown)</li>
     * </ol>
     *
     * <p>Deleting the old object <em>after</em> the DB update ensures the new image
     * is always reachable even if the old-object deletion fails.
     *
     * @param file   multipart image file supplied by the caller
     * @param zoneId identity zone this image belongs to
     * @return the S3 object key of the newly uploaded image
     * @throws java.util.NoSuchElementException if no image currently exists for this zone
     * @throws RuntimeException                 if the S3 upload or DB write fails
     */
    public String replaceBackgroundImage(MultipartFile file, String zoneId) {
        Optional<ZoneBackgroundImage> existing = repository.findByZoneId(zoneId);
        if (existing.isEmpty()) {
            throw new java.util.NoSuchElementException(
                    "No background image found for zone '" + zoneId + "' — use POST to upload one first");
        }
        String oldKey = existing.get().getS3Key();

        String contentType = resolveContentType(file);
        String extension   = resolveExtension(contentType);
        String newKey      = buildKey(zoneId, extension);

        logger.info("Replacing image in S3: zoneId={}, oldKey={}, newKey={}, sizeBytes={}",
                zoneId, oldKey, newKey, file.getSize());

        try {
            s3StorageManager.upload(bucket, newKey, file.getInputStream(), file.getSize(), contentType);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read replacement image file", e);
        }

        repository.save(new ZoneBackgroundImage(zoneId, newKey));
        logger.info("DB record updated to new key: zoneId={}, newKey={}", zoneId, newKey);

        // Delete old object after DB is consistent — best-effort, failure is logged only.
        try {
            s3StorageManager.delete(bucket, oldKey);
            logger.info("Old S3 object deleted: zoneId={}, oldKey={}", zoneId, oldKey);
        } catch (Exception e) {
            logger.warn("Failed to delete old S3 object (orphaned): zoneId={}, oldKey={}", zoneId, oldKey, e);
        }

        return newKey;
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    /**
     * Upload a background image for the given zone to S3 and persist the S3 key in the database.
     *
     * <p>If the zone already has a record the existing key is replaced (upsert).
     * The old S3 object is <em>not</em> removed — call
     * {@link #deleteBackgroundImage(String)} first if that is desired.
     *
     * @param file   multipart image file supplied by the caller
     * @param zoneId identity zone this image belongs to
     * @return the S3 object key of the newly uploaded image
     * @throws RuntimeException if the S3 upload fails or the file cannot be read
     */
    public String uploadBackgroundImage(MultipartFile file, String zoneId) {
        String contentType = resolveContentType(file);
        String extension   = resolveExtension(contentType);
        String s3Key       = buildKey(zoneId, extension);

        logger.info("Uploading image to S3: zoneId={}, key={}, contentType={}, sizeBytes={}",
                zoneId, s3Key, contentType, file.getSize());

        try {
            s3StorageManager.upload(bucket, s3Key, file.getInputStream(), file.getSize(), contentType);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read uploaded image file", e);
        }

        // Persist the zone → S3 key mapping so the image can be retrieved later.
        repository.save(new ZoneBackgroundImage(zoneId, s3Key));
        logger.info("DB record saved: zoneId={}, s3Key={}", zoneId, s3Key);

        return s3Key;
    }

    // -------------------------------------------------------------------------
    // Query
    // -------------------------------------------------------------------------

    /**
     * Return the active S3 key for the given zone from the database.
     *
     * @param zoneId the identity zone ID
     * @return the S3 key, or {@link Optional#empty()} if no image has been uploaded
     */
    public Optional<String> findS3KeyByZone(String zoneId) {
        return repository.findByZoneId(zoneId).map(ZoneBackgroundImage::getS3Key);
    }

    /**
     * Retrieve S3 object metadata (content-type, size, ETag, last-modified)
     * without downloading the image body.
     *
     * @param zoneId the identity zone ID (used for diagnostic logging only)
     * @param s3Key  the S3 object key
     * @return the HEAD response from S3
     */
    public HeadObjectResponse getObjectMetadata(String zoneId, String s3Key) {
        logger.debug("Fetching S3 object metadata: zoneId={}, key={}", zoneId, s3Key);
        return s3StorageManager.headObject(bucket, s3Key);
    }

    // -------------------------------------------------------------------------
    // Download
    // -------------------------------------------------------------------------

    /**
     * Download the raw image bytes from S3 as a streaming response.
     *
     * <p><strong>The caller is responsible for closing the returned stream.</strong>
     *
     * @param zoneId the identity zone ID (used for diagnostic logging only)
     * @param s3Key  the S3 object key
     * @return streaming S3 response
     */
    public ResponseInputStream<GetObjectResponse> downloadBackgroundImage(String zoneId, String s3Key) {
        logger.debug("Downloading image from S3: zoneId={}, key={}", zoneId, s3Key);
        return s3StorageManager.download(bucket, s3Key);
    }

    /**
     * Download an image from S3 and return it Base64-encoded together with metadata.
     *
     * @param zoneId the identity zone ID (used for diagnostic logging only)
     * @param s3Key  the S3 object key
     * @return encoded result containing content-type, sizes, and wall-clock encoding time
     * @throws IOException if the S3 stream cannot be read
     */
    public Base64ImageResult getImageAsBase64(String zoneId, String s3Key) throws IOException {
        logger.debug("Encoding image as Base64: zoneId={}, key={}", zoneId, s3Key);
        long start = System.currentTimeMillis();

        try (ResponseInputStream<GetObjectResponse> s3Stream = s3StorageManager.download(bucket, s3Key)) {
            String contentType = s3Stream.response().contentType() != null
                    ? s3Stream.response().contentType()
                    : "image/jpeg";
            // Stream through Base64 encoder — avoids holding both the raw bytes and the
            // encoded form in heap simultaneously.
            long originalBytes = s3Stream.response().contentLength() != null
                    ? s3Stream.response().contentLength()
                    : -1;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (OutputStream b64Out = Base64.getEncoder().wrap(baos)) {
                s3Stream.transferTo(b64Out);
            }
            String base64Data = baos.toString(StandardCharsets.UTF_8);
            long   encodingMs = System.currentTimeMillis() - start;
            return new Base64ImageResult(contentType, originalBytes, base64Data, encodingMs);
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    /**
     * Delete the active background image for the given zone.
     *
     * <p>The S3 object is deleted first. If S3 deletion succeeds the database record
     * is also removed. If no record exists for the zone {@code false} is returned.
     *
     * @param zoneId the identity zone ID
     * @return {@code true} if an image was found and removed, {@code false} otherwise
     */
    public boolean deleteBackgroundImage(String zoneId) {
        Optional<ZoneBackgroundImage> current = repository.findByZoneId(zoneId);
        if (current.isEmpty()) {
            logger.info("Delete requested but no image found in DB: zoneId={}", zoneId);
            return false;
        }
        String s3Key = current.get().getS3Key();
        logger.info("Deleting image from S3: zoneId={}, key={}", zoneId, s3Key);
        s3StorageManager.delete(bucket, s3Key);
        return repository.deleteByZoneId(zoneId);
    }

    // -------------------------------------------------------------------------
    // Presigned URL
    // -------------------------------------------------------------------------

    /**
     * Generate a presigned GET URL for an S3 object.
     *
     * @param zoneId        the identity zone ID (used for diagnostic logging only)
     * @param s3Key         the S3 object key
     * @param expiryMinutes how long the URL should remain valid (positive integer)
     * @return absolute presigned URL as a string
     */
    public String getPresignedUrl(String zoneId, String s3Key, long expiryMinutes) {
        logger.debug("Generating presigned URL: zoneId={}, key={}, expiryMinutes={}",
                zoneId, s3Key, expiryMinutes);
        return s3StorageManager.generatePresignedUrl(bucket, s3Key, expiryMinutes).toString();
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    /**
     * Build the canonical {@code s3://bucket/key} URI for a given key.
     *
     * @param s3Key the S3 object key
     * @return URI in {@code s3://bucket/key} form
     */
    public String buildS3Uri(String s3Key) {
        return "s3://" + bucket + "/" + s3Key;
    }

    private String buildKey(String zoneId, String extension) {
        return keyPrefix + "/" + zoneId + "/" + UUID.randomUUID() + "." + extension;
    }

    /**
     * Extract the bare MIME type from the file's content-type header, stripping any
     * parameters (e.g. {@code "image/jpeg; charset=utf-8"} → {@code "image/jpeg"}).
     */
    private static String resolveContentType(MultipartFile file) {
        String raw = file.getContentType();
        if (raw == null || raw.isBlank()) {
            return "application/octet-stream";
        }
        // Strip parameters like "; charset=utf-8" before returning
        return raw.split(";")[0].trim();
    }

    private static String resolveExtension(String contentType) {
        return switch (contentType.toLowerCase()) {
            case "image/png"  -> "png";
            case "image/webp" -> "webp";
            case "image/gif"  -> "gif";
            default           -> "jpg";
        };
    }

    // -------------------------------------------------------------------------
    // Inner record
    // -------------------------------------------------------------------------

    /**
     * Holds the result of a Base64 encoding operation.
     *
     * @param contentType   MIME type of the original image
     * @param originalBytes size of the raw image in bytes
     * @param base64Data    Base64-encoded image data (standard encoding, no line wrapping,
     *                      no data-URI prefix)
     * @param encodingMs    wall-clock time taken to download and encode the image
     */
    public record Base64ImageResult(
            String contentType,
            long   originalBytes,
            String base64Data,
            long   encodingMs) {

        /**
         * @return a CSS-embeddable data URI: {@code data:<contentType>;base64,<data>}
         */
        public String toDataUri() {
            return "data:" + contentType + ";base64," + base64Data;
        }
    }
}
