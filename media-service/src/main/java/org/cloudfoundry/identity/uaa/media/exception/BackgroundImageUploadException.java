package org.cloudfoundry.identity.uaa.media.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * Exception thrown when background image upload fails.
 * Maps to HTTP 422 Unprocessable Entity.
 */
public class BackgroundImageUploadException extends UaaException {
    
    public BackgroundImageUploadException(String message) {
        super("upload_failed", message, 422);
    }
    
    public BackgroundImageUploadException(String message, Throwable cause) {
        super("upload_failed", message, 422);
        initCause(cause);
    }
}
