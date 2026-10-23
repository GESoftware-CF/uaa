package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * REST endpoint for background image management.
 *
 * <ul>
 *   <li>POST   /background_images/upload – upload image for current zone to S3,
 *       store public URL in identity_zone.config.branding.backgroundImageUrl</li>
 *   <li>DELETE /background_images        – delete the zone's background image</li>
 * </ul>
 *
 * <p>The login page reads the background image URL directly from the identity zone
 * configuration — no GET API is needed.
 */
@RestController
@RequestMapping("/background_images")
@ConditionalOnProperty(name = {"AWS_REGION", "BACKGROUND_IMAGE_STORAGE_BUCKET", "BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES"})
public class BackgroundImageEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageEndpoint.class);

    private final BackgroundImageService backgroundImageService;

    public BackgroundImageEndpoint(BackgroundImageService backgroundImageService) {
        this.backgroundImageService = backgroundImageService;
    }

    // -------------------------------------------------------------------------
    // POST /background_images/upload  — upload
    // -------------------------------------------------------------------------

    /**
     * Upload a background image for the current identity zone.
     *
     * <p>The image is stored in S3 at the fixed key
     * {@code uaa/{zoneId}/background-image} and the public URL (with a {@code ?v=} cache-buster)
     * is persisted in the identity zone's config JSON at
     * {@code config.branding.backgroundImageUrl}.
     *
     * @param file multipart image file (PNG, JPEG, or WebP)
     * @return 200 OK on success
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> uploadBackgroundImage(
            @RequestParam("file") MultipartFile file) {

        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("POST /background_images/upload: zone={}, filename={}, size={}",
                zoneId, file.getOriginalFilename(), file.getSize());

        backgroundImageService.uploadBackgroundImage(file, zoneId);

        return ResponseEntity.ok().build();
    }

    // -------------------------------------------------------------------------
    // DELETE /background_images
    // -------------------------------------------------------------------------

    /**
     * Delete the background image for the current identity zone.
     *
     * @return 204 No Content on success, 404 if no image exists for this zone
     */
    @DeleteMapping
    public ResponseEntity<Void> deleteBackgroundImage() {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("DELETE /background_images: zone={}", zoneId);
        boolean deleted = backgroundImageService.deleteBackgroundImage(zoneId);
        return deleted
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
