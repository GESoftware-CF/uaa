package org.cloudfoundry.identity.uaa.media.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * Exception thrown when uploaded file is too large.
 * Maps to HTTP 413 Payload Too Large.
 */
public class PayloadTooLargeException extends UaaException {
    
    public PayloadTooLargeException(String message) {
        super("payload_too_large", message, 413);
    }
}
