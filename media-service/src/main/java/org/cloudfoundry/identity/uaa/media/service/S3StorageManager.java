package org.cloudfoundry.identity.uaa.media.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;

import java.io.InputStream;
import java.net.URL;
import java.time.Duration;

/**
 * Manages uploads and downloads to/from AWS S3.
 */
@Service
public class S3StorageManager {

    private static final Logger logger = LoggerFactory.getLogger(S3StorageManager.class);

    private static final long DEFAULT_PRESIGN_DURATION_MINUTES = 60;

    private final String awsRegion;
    private S3Client s3Client;
    private S3Presigner s3Presigner;

    public S3StorageManager(@Value("${AWS_REGION}") String awsRegion) {
        this.awsRegion = awsRegion;
    }

    @PostConstruct
    public void init() {
        logger.info("Initializing S3StorageManager: region={}", awsRegion);
        Region region = Region.of(awsRegion);
        DefaultCredentialsProvider credentials = DefaultCredentialsProvider.create();
        this.s3Client = S3Client.builder()
            .region(region)
            .credentialsProvider(credentials)
            .build();
        this.s3Presigner = S3Presigner.builder()
            .region(region)
            .credentialsProvider(credentials)
            .build();
    }

    @PreDestroy
    public void destroy() {
        if (s3Client != null) {
            s3Client.close();
        }
        if (s3Presigner != null) {
            s3Presigner.close();
        }
    }

    /**
     * Upload a file to S3.
     *
     * @param bucket        S3 bucket name
     * @param key           S3 object key
     * @param inputStream   file input stream
     * @param contentLength file size in bytes
     * @param contentType   MIME type
     */
    public void upload(String bucket, String key, InputStream inputStream,
                       long contentLength, String contentType) {
        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(contentType)
                .contentLength(contentLength)
                .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, contentLength));
            logger.info("Successfully uploaded to S3: s3://{}/{}", bucket, key);

        } catch (Exception e) {
            logger.error("S3 upload failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to upload image to S3", e);
        }
    }

    /**
     * Download an object from S3 as a streaming response.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key
     * @return ResponseInputStream containing image bytes and S3 metadata
     */
    public ResponseInputStream<GetObjectResponse> download(String bucket, String key) {
        try {
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();
            logger.debug("Downloading from S3: bucket={}, key={}", bucket, key);
            return s3Client.getObject(getObjectRequest);
        } catch (Exception e) {
            logger.error("S3 download failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to download image from S3", e);
        }
    }

    /**
     * Generate a presigned GET URL for an S3 object.
     *
     * @param bucket          S3 bucket name
     * @param key             S3 object key
     * @param expiryMinutes   validity duration in minutes (positive value)
     * @return presigned URL valid for the specified duration
     */
    public URL generatePresignedUrl(String bucket, String key, long expiryMinutes) {
        GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
            .signatureDuration(Duration.ofMinutes(expiryMinutes > 0 ? expiryMinutes : DEFAULT_PRESIGN_DURATION_MINUTES))
            .getObjectRequest(GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build())
            .build();

        PresignedGetObjectRequest presignedRequest = s3Presigner.presignGetObject(presignRequest);
        logger.debug("Generated presigned URL: bucket={}, key={}, expiryMinutes={}", bucket, key, expiryMinutes);
        return presignedRequest.url();
    }

    /**
     * Retrieve metadata (content-type, content-length) for an S3 object without downloading it.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key
     * @return HeadObjectResponse with object metadata
     * @throws RuntimeException if the object does not exist or the request fails
     */
    public HeadObjectResponse headObject(String bucket, String key) {
        try {
            return s3Client.headObject(HeadObjectRequest.builder().bucket(bucket).key(key).build());
        } catch (Exception e) {
            logger.error("S3 headObject failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to retrieve S3 object metadata", e);
        }
    }

    /**
     * Build the plain, unsigned HTTPS URL for an S3 object.
     *
     * <p>Returns {@code https://{bucket}.s3.{region}.amazonaws.com/{key}}.
     * No credentials, tokens, or query parameters are attached — the object must
     * be publicly accessible via bucket policy for this URL to resolve.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key
     * @return plain public HTTPS URL for the object
     */
    public String getDirectUrl(String bucket, String key) {
        String url = String.format("https://%s.s3.%s.amazonaws.com/%s", bucket, awsRegion, key);
        logger.debug("Direct S3 URL constructed: {}", url);
        return url;
    }

    /**
     * Delete an object from S3.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key
     * @throws RuntimeException if the deletion fails
     */
    public void delete(String bucket, String key) {
        try {
            s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
            logger.info("Deleted S3 object: bucket={}, key={}", bucket, key);
        } catch (Exception e) {
            logger.error("S3 delete failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to delete image from S3", e);
        }
    }
}
