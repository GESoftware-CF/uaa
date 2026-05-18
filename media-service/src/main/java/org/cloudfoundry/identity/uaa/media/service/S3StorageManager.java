package org.cloudfoundry.identity.uaa.media.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.InputStream;

/**
 * Manages uploads and deletions to/from AWS S3.
 *
 * <p>Only the operations required by the background-image upload flow are exposed:
 * {@link #upload}, {@link #getDirectUrl}, and {@link #delete}.
 */
@Service
public class S3StorageManager {

    private static final Logger logger = LoggerFactory.getLogger(S3StorageManager.class);

    private final String awsRegion;
    private S3Client s3Client;

    public S3StorageManager(@Value("${cloud.aws.region}") String awsRegion) {
        this.awsRegion = awsRegion;
    }

    @PostConstruct
    public void init() {
        logger.info("Initializing S3StorageManager: region={}", awsRegion);
        this.s3Client = S3Client.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    @PreDestroy
    public void destroy() {
        if (s3Client != null) {
            s3Client.close();
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
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(bucket)
                            .key(key)
                            .contentType(contentType)
                            .contentLength(contentLength)
                            .build(),
                    RequestBody.fromInputStream(inputStream, contentLength));
            logger.info("Successfully uploaded to S3: s3://{}/{}", bucket, key);
        } catch (Exception e) {
            logger.error("S3 upload failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to upload image to S3", e);
        }
    }

    /**
     * Build the plain, unsigned HTTPS URL for an S3 object.
     *
     * <p>Returns {@code https://{bucket}.s3.{region}.amazonaws.com/{key}}.
     * The object must be publicly readable via bucket policy for this URL to resolve.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key (pass an empty string to obtain just the bucket base URL)
     * @return public HTTPS URL for the object
     */
    public String getDirectUrl(String bucket, String key) {
        return String.format("https://%s.s3.%s.amazonaws.com/%s", bucket, awsRegion, key);
    }

    /**
     * Delete an object from S3.
     *
     * @param bucket S3 bucket name
     * @param key    S3 object key
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
