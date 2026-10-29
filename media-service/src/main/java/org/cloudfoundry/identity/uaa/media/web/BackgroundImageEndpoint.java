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
 * <p>POST uploads a PNG or JPEG under a unique S3 key and stores its relative reference in
 * {@code identity_zone.config.branding.backgroundImageUrl}. DELETE clears that reference and
 * removes the object on a best-effort basis. The login URL is built from the stored reference at
 * render time; when absent or invalid, the templates use their bundled static image.
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
        * <p>The image is stored in S3 at
        * {@code {basePath}/{zoneId}/{timestamp}-{random}.{png|jpg}}. The database stores only the
        * relative reference {@code {zoneId}/{timestamp}-{random}.{png|jpg}}; the CloudFront URL is
        * constructed when the login page is rendered.
     *
    * @param file multipart image file (PNG or JPEG)
    * @return 200 OK with no response body on success
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
