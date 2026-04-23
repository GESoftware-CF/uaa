package org.cloudfoundry.identity.uaa.media.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * Exception thrown when background image is not found for a zone.
 * Maps to HTTP 404 Not Found.
 */
public class BackgroundImageNotFoundException extends UaaException {
    
    public BackgroundImageNotFoundException(String message) {
        super("not_found", message, 404);
    }
    
    public BackgroundImageNotFoundException(String zoneId, String message) {
        super("not_found", 
            String.format("Background image not found for zone '%s': %s", zoneId, message), 
            404);
    }
}
