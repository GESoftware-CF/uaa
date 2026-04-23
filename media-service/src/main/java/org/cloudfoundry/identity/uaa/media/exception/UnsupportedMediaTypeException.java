package org.cloudfoundry.identity.uaa.media.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * Exception thrown when uploaded file type is not supported.
 * Maps to HTTP 415 Unsupported Media Type.
 */
public class UnsupportedMediaTypeException extends UaaException {
    
    public UnsupportedMediaTypeException(String message) {
        super("unsupported_media_type", message, 415);
    }
}
