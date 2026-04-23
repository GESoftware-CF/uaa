package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.springframework.security.core.Authentication;

/** Audit event for an image operation on an identity zone. */
public class BackgroundImageEvent extends AbstractUaaEvent {
    private final AuditEventType type;
    private final String data;
    private final String outcome;
    private final String operationId;

    public BackgroundImageEvent(String zoneId, AuditEventType type, String data, Authentication authentication,
                                String outcome, String operationId) {
        super(zoneId, authentication, zoneId);
        this.type = type;
        this.data = data;
        this.outcome = outcome;
        this.operationId = operationId;
    }

    public String getOutcome() {
        return outcome;
    }

    public String getOperationId() {
        return operationId;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(getIdentityZoneId(), type, getOrigin(getAuthentication()), data);
    }
}