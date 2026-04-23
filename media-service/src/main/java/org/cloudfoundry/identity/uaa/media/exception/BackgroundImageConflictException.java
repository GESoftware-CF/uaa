package org.cloudfoundry.identity.uaa.media.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * Exception thrown when a background image already exists for a zone.
 * Maps to HTTP 409 Conflict.
 */
public class BackgroundImageConflictException extends UaaException {
    
    public BackgroundImageConflictException(String message) {
        super("conflict", message, 409);
    }
    
    public BackgroundImageConflictException(String zoneId) {
        super("conflict", 
            String.format("Background image already exists for zone '%s'", zoneId), 
            409);
    }
}
