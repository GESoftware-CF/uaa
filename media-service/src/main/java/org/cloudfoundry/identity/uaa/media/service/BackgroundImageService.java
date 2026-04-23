package org.cloudfoundry.identity.uaa.media.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.UUID;

/**
 * Service for uploading background images to S3.
 */
@Service
public class BackgroundImageService {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageService.class);

    private final S3StorageManager s3StorageManager;
    private final String storageBucket;

    public BackgroundImageService(
            S3StorageManager s3StorageManager,
            @Value("${AWS_S3_BUCKET}") String storageBucket) {
        this.s3StorageManager = s3StorageManager;
        this.storageBucket = storageBucket;
    }

    /**
     * Upload a background image to S3.
     *
     * @param file uploaded image file
     * @param identityZoneId zone ID (used as part of S3 key)
     * @return the S3 URL of the uploaded image
     * @throws RuntimeException if upload fails
     */
    public String uploadBackgroundImage(MultipartFile file, String identityZoneId) {
        try {
            String filename = file.getOriginalFilename() != null ? file.getOriginalFilename() : "image";
            String s3Key = String.format("background/%s/%s/%s", identityZoneId, UUID.randomUUID(), filename);

            logger.info("Uploading background image to S3: bucket={}, key={}", storageBucket, s3Key);

            String url = s3StorageManager.upload(
                storageBucket,
                s3Key,
                file.getInputStream(),
                file.getSize(),
                file.getContentType()
            );

            logger.info("Background image uploaded successfully: url={}", url);
            return url;

        } catch (IOException e) {
            logger.error("Failed to read uploaded file for zone={}", identityZoneId, e);
            throw new RuntimeException("Failed to read uploaded file", e);
        }
    }
}
