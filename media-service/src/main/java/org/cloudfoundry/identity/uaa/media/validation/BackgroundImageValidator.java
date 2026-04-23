package org.cloudfoundry.identity.uaa.media.validation;

import org.cloudfoundry.identity.uaa.media.exception.UnsupportedMediaTypeException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Set;

/**
 * Validator for background image uploads.
 * Performs fail-fast validation before expensive S3 operations.
 */
@Component
public class BackgroundImageValidator {

    private final MimeTypeDetector mimeTypeDetector;
    private final long minSizeBytes;
    private final long maxSizeBytes;
    private final Set<String> allowedMimeTypes;

    public BackgroundImageValidator(
            MimeTypeDetector mimeTypeDetector,
            @Value("${background-image.validation.min-size-bytes:10240}") long minSizeBytes,
            @Value("${background-image.validation.max-size-bytes:10485760}") long maxSizeBytes,
            @Value("${background-image.validation.allowed-mime-types:image/png,image/jpeg,image/webp}") Set<String> allowedMimeTypes) {
        this.mimeTypeDetector = mimeTypeDetector;
        this.minSizeBytes = minSizeBytes;
        this.maxSizeBytes = maxSizeBytes;
        this.allowedMimeTypes = allowedMimeTypes;
    }

    /**
     * Validate an uploaded background image file.
     * Checks MIME type via magic bytes and file size bounds.
     *
     * @param file the uploaded file
     * @return the detected MIME type
     * @throws IllegalArgumentException if file is null or empty
     * @throws UnsupportedMediaTypeException if MIME type is not allowed
     * @throws org.cloudfoundry.identity.uaa.media.exception.PayloadTooLargeException if file size is out of bounds
     * @throws IOException if reading file fails
     */
    public String validate(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File cannot be null or empty");
        }

        // Validate file size
        long size = file.getSize();
        if (size < minSizeBytes) {
            throw new IllegalArgumentException(
                String.format("File too small: %d bytes (minimum: %d bytes)", size, minSizeBytes)
            );
        }
        if (size > maxSizeBytes) {
            throw new org.cloudfoundry.identity.uaa.media.exception.PayloadTooLargeException(
                String.format("File too large: %d bytes (maximum: %d bytes)", size, maxSizeBytes)
            );
        }

        // Detect MIME type via magic bytes (prevents Content-Type header spoofing)
        String detectedMimeType = mimeTypeDetector.detectMimeType(file.getInputStream());
        
        if (detectedMimeType == null) {
            throw new UnsupportedMediaTypeException("Unable to detect image format. File may be corrupted.");
        }
        
        if (!allowedMimeTypes.contains(detectedMimeType)) {
            throw new UnsupportedMediaTypeException(
                String.format("Unsupported MIME type: %s. Allowed types: %s", 
                    detectedMimeType, allowedMimeTypes)
            );
        }

        return detectedMimeType;
    }

    /**
     * Sanitize a filename by removing dangerous characters and path traversal sequences.
     * Replaces whitespace with hyphens and removes all non-alphanumeric characters except dots and hyphens.
     *
     * @param filename the original filename
     * @return sanitized filename
     */
    public String sanitizeFilename(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "background.img";
        }
        
        // Remove path components (e.g., ../, ./, /)
        filename = filename.replaceAll(".*[\\\\/]", "");
        
        // Replace whitespace with hyphens
        filename = filename.replaceAll("\\s+", "-");
        
        // Remove all characters except alphanumeric, dots, and hyphens
        filename = filename.replaceAll("[^a-zA-Z0-9.-]", "");
        
        // Prevent empty or hidden filenames
        if (filename.isEmpty() || filename.startsWith(".")) {
            return "background.img";
        }
        
        // Limit length
        if (filename.length() > 255) {
            filename = filename.substring(0, 255);
        }
        
        return filename;
    }
}
