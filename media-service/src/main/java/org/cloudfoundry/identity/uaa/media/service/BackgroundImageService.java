package org.cloudfoundry.identity.uaa.media.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

import java.io.IOException;
import java.net.URL;
import java.util.UUID;

/**
 * Service for uploading and downloading background images via S3.
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private final S3StorageManager s3StorageManager;
    private final String bucketName;

    public BackgroundImageService(S3StorageManager s3StorageManager,
                                  @Value("${AWS_S3_BUCKET}") String bucketName) {
        this.s3StorageManager = s3StorageManager;
        this.bucketName = bucketName;
    }

    /**
     * Upload a background image for the given zone to S3.
     *
     * @param file   the image file to upload
     * @param zoneId the identity zone ID
     * @return S3 URI of the uploaded object
     */
    public String uploadBackgroundImage(MultipartFile file, String zoneId) {
        String key = buildKey(zoneId, UUID.randomUUID().toString(), file.getOriginalFilename());
        try {
            logger.info("Uploading background image: bucket={}, key={}", bucketName, key);
            return s3StorageManager.upload(bucketName, key, file.getInputStream(),
                    file.getSize(), file.getContentType());
        } catch (IOException e) {
            logger.error("Failed to read uploaded file: {}", file.getOriginalFilename(), e);
            throw new RuntimeException("Failed to read uploaded file", e);
        }
    }

    /**
     * Download the raw background image for the given zone as a streaming S3 response.
     * Logs S3 fetch latency for performance monitoring.
     *
     * @param zoneId   the identity zone ID
     * @param s3Key    the S3 object key (returned from upload)
     * @return ResponseInputStream with image bytes and metadata
     */
    public ResponseInputStream<GetObjectResponse> downloadBackgroundImage(String zoneId, String s3Key) {
        logger.debug("Downloading background image: zone={}, key={}", zoneId, s3Key);
        long start = System.currentTimeMillis();
        ResponseInputStream<GetObjectResponse> response = s3StorageManager.download(bucketName, s3Key);
        long elapsed = System.currentTimeMillis() - start;
        logger.info("S3 download initiated: zone={}, key={}, s3InitMs={}", zoneId, s3Key, elapsed);
        return response;
    }

    /**
     * Build the S3 key for a background image.
     *
     * @param zoneId   identity zone ID
     * @param imageId  unique image ID
     * @param filename original filename
     * @return S3 key string
     */
    public static String buildKey(String zoneId, String imageId, String filename) {
        return "background_images/" + zoneId + "/" + imageId + "_" + filename;
    }

    /**
     * Generate a presigned URL for the given S3 key that expires after the specified duration.
     *
     * @param zoneId        the identity zone ID (for logging)
     * @param s3Key         the S3 object key
     * @param expiryMinutes how long the URL is valid (in minutes); minimum 1, maximum 10080 (7 days)
     * @return presigned URL string
     */
    public String getPresignedUrl(String zoneId, String s3Key, long expiryMinutes) {
        long clampedExpiry = Math.max(1, Math.min(10080, expiryMinutes));
        logger.info("Generating presigned URL: zone={}, key={}, expiryMinutes={}", zoneId, s3Key, clampedExpiry);
        URL url = s3StorageManager.generatePresignedUrl(bucketName, s3Key, clampedExpiry);
        return url.toString();
    }

    /**
     * Download the background image from S3 and return it as a Base64-encoded string.
     *
     * <p>The result can be used directly as a CSS/HTML data URI:
     * {@code data:<contentType>;base64,<encodedData>}
     *
     * @param zoneId the identity zone ID (for logging)
     * @param s3Key  the S3 object key (returned from upload)
     * @return {@link Base64ImageResult} containing the Base64 payload, content-type,
     *         original byte size, and encoding duration
     */
    public Base64ImageResult getImageAsBase64(String zoneId, String s3Key) {
        logger.info("Encoding background image to Base64: zone={}, key={}", zoneId, s3Key);
        long start = System.currentTimeMillis();

        try (ResponseInputStream<GetObjectResponse> stream = s3StorageManager.download(bucketName, s3Key)) {
            GetObjectResponse meta = stream.response();
            String contentType = meta.contentType() != null ? meta.contentType() : "image/jpeg";
            byte[] imageBytes = stream.readAllBytes();
            String encoded = java.util.Base64.getEncoder().encodeToString(imageBytes);
            long elapsedMs = System.currentTimeMillis() - start;

            logger.info("Base64 encoding complete: zone={}, key={}, originalBytes={}, encodedChars={}, totalMs={}",
                    zoneId, s3Key, imageBytes.length, encoded.length(), elapsedMs);

            return new Base64ImageResult(encoded, contentType, imageBytes.length, elapsedMs);
        } catch (java.io.IOException e) {
            logger.error("Failed to read image bytes for Base64 encoding: zone={}, key={}", zoneId, s3Key, e);
            throw new RuntimeException("Failed to encode image to Base64", e);
        }
    }

    /**
     * Immutable result holder for a Base64-encoded image.
     *
     * @param base64Data    Base64-encoded image bytes
     * @param contentType   MIME type (e.g. {@code image/jpeg})
     * @param originalBytes number of raw image bytes before encoding
     * @param encodingMs    total time in milliseconds to fetch and encode
     */
    public record Base64ImageResult(
            String base64Data,
            String contentType,
            long originalBytes,
            long encodingMs) {

        /** Convenience method returning a ready-to-use HTML/CSS data URI. */
        public String toDataUri() {
            return "data:" + contentType + ";base64," + base64Data;
        }
    }

    /**
     * Retrieve S3 object metadata (content-type, content-length, ETag, last-modified) for the given key.
     *
     * @param zoneId the identity zone ID (for logging)
     * @param s3Key  the S3 object key
     * @return HeadObjectResponse containing metadata
     */
    public HeadObjectResponse getObjectMetadata(String zoneId, String s3Key) {
        logger.debug("Fetching S3 metadata: zone={}, key={}", zoneId, s3Key);
        return s3StorageManager.headObject(bucketName, s3Key);
    }
}
