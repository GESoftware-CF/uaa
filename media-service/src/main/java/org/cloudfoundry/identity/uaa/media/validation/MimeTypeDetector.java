package org.cloudfoundry.identity.uaa.media.validation;

import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Utility for detecting MIME types via magic-byte (file signature) analysis.
 * Prevents MIME-type spoofing by reading the actual file header bytes.
 */
@Component
public class MimeTypeDetector {

    // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
    private static final byte[] PNG_SIGNATURE = new byte[]{
        (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };
    
    // JPEG magic bytes: FF D8 FF
    private static final byte[] JPEG_SIGNATURE = new byte[]{
        (byte) 0xFF, (byte) 0xD8, (byte) 0xFF
    };
    
    // WebP magic bytes: RIFF (bytes 0-3) + WEBP (bytes 8-11)
    private static final byte[] WEBP_RIFF = new byte[]{0x52, 0x49, 0x46, 0x46};
    private static final byte[] WEBP_WEBP = new byte[]{0x57, 0x45, 0x42, 0x50};

    /**
     * Detect the MIME type of a file by reading its magic bytes.
     * Supports PNG, JPEG, and WebP formats.
     *
     * @param inputStream the file input stream (must support mark/reset)
     * @return the detected MIME type (e.g., "image/png"), or null if unrecognized
     * @throws IOException if reading from the stream fails
     */
    public String detectMimeType(InputStream inputStream) throws IOException {
        if (!inputStream.markSupported()) {
            inputStream = new BufferedInputStream(inputStream);
        }
        
        // Read first 12 bytes for magic-byte analysis
        byte[] header = new byte[12];
        inputStream.mark(12);
        int bytesRead = inputStream.read(header, 0, 12);
        inputStream.reset();  // Reset to allow streaming to S3
        
        if (bytesRead < 3) {
            return null;  // Insufficient data
        }
        
        // Check PNG signature (8 bytes)
        if (bytesRead >= 8 && matches(header, 0, PNG_SIGNATURE)) {
            return "image/png";
        }
        
        // Check JPEG signature (3 bytes)
        if (matches(header, 0, JPEG_SIGNATURE)) {
            return "image/jpeg";
        }
        
        // Check WebP signature (RIFF at 0-3, WEBP at 8-11)
        if (bytesRead >= 12 && 
            matches(header, 0, WEBP_RIFF) && 
            matches(header, 8, WEBP_WEBP)) {
            return "image/webp";
        }
        
        return null;  // Unrecognized format
    }

    /**
     * Check if bytes match a signature pattern starting at an offset
     */
    private boolean matches(byte[] data, int offset, byte[] signature) {
        for (int i = 0; i < signature.length; i++) {
            if (data[offset + i] != signature[i]) {
                return false;
            }
        }
        return true;
    }
}
