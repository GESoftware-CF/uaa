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
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.InputStream;

/**
 * Manages uploads to AWS S3 using the synchronous S3Client.
 */
@Service
public class S3StorageManager {

    private static final Logger logger = LoggerFactory.getLogger(S3StorageManager.class);

    private final String awsRegion;
    private S3Client s3Client;

    public S3StorageManager(@Value("${AWS_REGION}") String awsRegion) {
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
     * @return S3 URI of the uploaded object
     */
    public String upload(String bucket, String key, InputStream inputStream,
                         long contentLength, String contentType) {
        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(contentType)
                .contentLength(contentLength)
                .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, contentLength));

            String url = String.format("s3://%s/%s", bucket, key);
            logger.info("Successfully uploaded to S3: {}", url);
            return url;

        } catch (Exception e) {
            logger.error("S3 upload failed: bucket={}, key={}", bucket, key, e);
            throw new RuntimeException("Failed to upload image to S3", e);
        }
    }
}
