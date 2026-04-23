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
        String key = "background_images/" + zoneId + "/" + UUID.randomUUID() + "_" + file.getOriginalFilename();
        try {
            logger.info("Uploading background image: bucket={}, key={}", bucketName, key);
            return s3StorageManager.upload(bucketName, key, file.getInputStream(),
                    file.getSize(), file.getContentType());
        } catch (IOException e) {
            logger.error("Failed to read uploaded file: {}", file.getOriginalFilename(), e);
            throw new RuntimeException("Failed to read uploaded file", e);
        }
    }
}

