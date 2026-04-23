package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * REST endpoint for background image upload.
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
     * @return 201 Created with S3 URL
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> uploadBackgroundImage(@RequestParam("file") MultipartFile file) {
        String zoneId = IdentityZoneHolder.get().getId();

        logger.info("POST /background_images: zone={}, filename={}, size={}", zoneId, file.getOriginalFilename(), file.getSize());

        String url = backgroundImageService.uploadBackgroundImage(file, zoneId);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("url", url));
    }
}
