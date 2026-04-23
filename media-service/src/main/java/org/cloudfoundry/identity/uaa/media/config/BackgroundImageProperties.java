package org.cloudfoundry.identity.uaa.media.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.util.Set;

/**
 * Configuration properties for background image feature.
 * Prefix: background-image
 */
@Data
@Validated
@ConfigurationProperties(prefix = "background-image")
public class BackgroundImageProperties {

    /**
     * Enable/disable the background image feature
     */
    private boolean enabled = true;

    /**
     * Storage configuration
     */
    private Storage storage = new Storage();

    /**
     * Validation rules
     */
    private Validation validation = new Validation();

    @Data
    public static class Storage {
        /**
         * S3 bucket name for background images
         */
        @NotBlank(message = "Storage bucket must be configured")
        private String bucket;

        /**
         * S3 key prefix (folder)
         */
        private String keyPrefix = "media";
    }

    @Data
    public static class Validation {
        /**
         * Minimum file size in bytes (default: 10 KB)
         */
        @Min(1024)
        private long minSizeBytes = 10240;

        /**
         * Maximum file size in bytes (default: 10 MB)
         */
        @Min(10240)
        @Max(52428800) // 50 MB absolute max
        private long maxSizeBytes = 10485760;

        /**
         * Allowed MIME types
         */
        private Set<String> allowedMimeTypes = Set.of("image/png", "image/jpeg", "image/webp");
    }
}
