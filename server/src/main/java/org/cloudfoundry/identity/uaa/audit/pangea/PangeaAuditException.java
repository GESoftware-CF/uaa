package org.cloudfoundry.identity.uaa.audit.pangea;

public class PangeaAuditException extends RuntimeException {
    private final String reasonCode;

    public PangeaAuditException(String reasonCode) {
        this(reasonCode, null);
    }

    public PangeaAuditException(String reasonCode, Throwable cause) {
        super("Pangea audit failure: " + reasonCode, cause);
        this.reasonCode = reasonCode;
    }

    public String getReasonCode() {
        return reasonCode;
    }
}