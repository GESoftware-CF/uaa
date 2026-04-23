package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.model.BackgroundImage;
import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * REST endpoint for background image management.
 * Provides upload and download capabilities scoped to identity zones.
 */
@RestController
@RequestMapping("/background_images")
public class BackgroundImageEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageEndpoint.class);

    private final BackgroundImageService backgroundImageService;

    public BackgroundImageEndpoint(BackgroundImageService backgroundImageService) {
        this.backgroundImageService = backgroundImageService;
    }

    /**
     * Upload a background image for the current zone.
     * POST /background_images
     *
     * @param file uploaded image file (multipart/form-data)
     * @return 201 Created with BackgroundImage metadata
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<BackgroundImage> uploadBackgroundImage(@RequestParam("file") MultipartFile file) {
        String zoneId = IdentityZoneHolder.get().getId();
        String userId = getCurrentUserId();
        
        logger.info("POST /background_images: zone={}, user={}, filename={}, size={}",
            zoneId, userId, file.getOriginalFilename(), file.getSize());
        
        BackgroundImage created = backgroundImageService.uploadBackgroundImage(file, zoneId, userId);
        
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }


    /**
     * Extract user ID from Spring Security context
     */
    private String getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "unknown";
    }
}
