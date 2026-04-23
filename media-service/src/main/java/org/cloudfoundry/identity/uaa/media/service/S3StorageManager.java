package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.media.exception.BackgroundImageUploadException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.transfer.s3.S3TransferManager;
import software.amazon.awssdk.transfer.s3.model.CompletedUpload;
import software.amazon.awssdk.transfer.s3.model.Upload;
import software.amazon.awssdk.transfer.s3.model.UploadRequest;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.InputStream;
import java.time.Duration;

/**
 * Service for uploading and downloading background images to/from AWS S3.
 * Uses S3 TransferManager for efficient multi-part uploads.
 */
@Service
public class S3StorageManager {

    private static final Logger logger = LoggerFactory.getLogger(S3StorageManager.class);

    private final String awsRegion;
    private final int maxConcurrency;
    private final long multipartThresholdBytes;
    
    private S3Client s3Client;
    private S3TransferManager transferManager;

    public S3StorageManager(
            @Value("${aws.region}") String awsRegion,
            @Value("${aws.s3.max-concurrency:50}") int maxConcurrency,
            @Value("${aws.s3.multipart-threshold-bytes:8388608}") long multipartThresholdBytes) {
        this.awsRegion = awsRegion;
        this.maxConcurrency = maxConcurrency;
        this.multipartThresholdBytes = multipartThresholdBytes;
    }

    @PostConstruct
    public void init() {
        logger.info("Initializing S3StorageManager: region={}, maxConcurrency={}, multipartThreshold={}",
            awsRegion, maxConcurrency, multipartThresholdBytes);
        
        // Create S3 client with CRT HTTP client for high throughput
        this.s3Client = S3Client.builder()
            .region(Region.of(awsRegion))
            .credentialsProvider(DefaultCredentialsProvider.create())
            .httpClient(AwsCrtHttpClient.builder()
                .maxConcurrency(maxConcurrency)
                .connectionMaxIdleTime(Duration.ofSeconds(60))
                .build())
            .build();
        
        // Create Transfer Manager for multipart uploads
        this.transferManager = S3TransferManager.builder()
            .s3Client(s3Client)
            .build();
    }

    @PreDestroy
    public void destroy() {
        if (transferManager != null) {
            transferManager.close();
        }
        if (s3Client != null) {
            s3Client.close();
        }
    }

    /**
     * Upload a file to S3 using streaming with automatic multipart for large files.
     *
     * @param bucket S3 bucket name
     * @param key S3 object key
     * @param inputStream file input stream
     * @param contentLength file size in bytes
     * @param contentType MIME type
     * @return S3 object URL
     * @throws BackgroundImageUploadException if upload fails
     */
    public String upload(String bucket, String key, InputStream inputStream, 
                        long contentLength, String contentType) {
        try {
            logger.debug("Uploading to S3: bucket={}, key={}, size={}, type={}", 
                bucket, key, contentLength, contentType);
            
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(contentType)
                .contentLength(contentLength)
                .build();
            
            UploadRequest uploadRequest = UploadRequest.builder()
                .putObjectRequest(putObjectRequest)
                .requestBody(RequestBody.fromInputStream(inputStream, contentLength))
                .build();
            
            Upload upload = transferManager.upload(uploadRequest);
            CompletedUpload completed = upload.completionFuture().join();
            
            String url = String.format("s3://%s/%s", bucket, key);
            logger.info("Successfully uploaded to S3: {}", url);
            return url;
            
        } catch (Exception e) {
            logger.error("S3 upload failed: bucket={}, key={}", bucket, key, e);
            throw new BackgroundImageUploadException("Failed to upload image to S3", e);
        }
    }

    /**
     * Download a file from S3 as a byte array.
     *
     * @param bucket S3 bucket name
     * @param key S3 object key
     * @return file bytes
     * @throws BackgroundImageUploadException if download fails
     */
    public byte[] download(String bucket, String key) {
        try {
            logger.debug("Downloading from S3: bucket={}, key={}", bucket, key);
            
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();
            
            byte[] bytes = s3Client.getObjectAsBytes(getObjectRequest).asByteArray();
            logger.debug("Successfully downloaded {} bytes from S3", bytes.length);
            return bytes;
            
        } catch (NoSuchKeyException e) {
            logger.error("S3 object not found: bucket={}, key={}", bucket, key);
            throw new BackgroundImageUploadException("Image not found in S3 storage");
        } catch (Exception e) {
            logger.error("S3 download failed: bucket={}, key={}", bucket, key, e);
            throw new BackgroundImageUploadException("Failed to download image from S3", e);
        }
    }

    /**
     * Delete an object from S3.
     *
     * @param bucket S3 bucket name
     * @param key S3 object key
     */
    public void delete(String bucket, String key) {
        try {
            logger.debug("Deleting from S3: bucket={}, key={}", bucket, key);
            
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .build();
            
            s3Client.deleteObject(deleteObjectRequest);
            logger.info("Successfully deleted from S3: bucket={}, key={}", bucket, key);
            
        } catch (Exception e) {
            logger.error("S3 delete failed: bucket={}, key={}", bucket, key, e);
            // Don't throw - allow soft-delete to proceed even if S3 cleanup fails
        }
    }
}
