package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class BackgroundImageEventTest {
    @Test
    void shouldCreateAuditRecordWithTargetZoneAndPassedData() {
        String zoneId = "target-zone";
        String data = "outcome=SUCCESS; op=operation";
        var event = new BackgroundImageEvent(zoneId, AuditEventType.BackgroundImageUploadedEvent,
            data, null, "SUCCESS", "operation");

        AuditEvent audit = event.getAuditEvent();

        assertThat(audit.getType()).isEqualTo(AuditEventType.BackgroundImageUploadedEvent);
        assertThat(audit.getPrincipalId()).isEqualTo(zoneId);
        assertThat(audit.getIdentityZoneId()).isEqualTo(zoneId);
        assertThat(audit.getData()).isEqualTo(data);
        assertThat(audit.getOrigin()).isNull();
        assertThatCode(event::getAuditEvent).doesNotThrowAnyException();
    }

    @Test
    void shouldExposeStructuredFieldsWithoutChangingAuditRecord() {
        String data = "outcome=FAILURE; op=operation-2; stage=dbUpdate";
        var event = new BackgroundImageEvent("target-zone", AuditEventType.BackgroundImageReplacedEvent,
            data, null, "FAILURE", "operation-2");

        assertThat(event.getZoneId()).isEqualTo("target-zone");
        assertThat(event.getType()).isEqualTo(AuditEventType.BackgroundImageReplacedEvent);
        assertThat(event.getData()).isEqualTo(data);
        assertThat(event.getOutcome()).isEqualTo("FAILURE");
        assertThat(event.getOperationId()).isEqualTo("operation-2");
        assertThat(event.getAuditEvent().getData()).isEqualTo(data);
    }

    @Test
    void preservesExplicitOutcomeAndOperationId() {
        String data = "outcome=SUCCESS; op=from-data";
        var event = new BackgroundImageEvent("target-zone", AuditEventType.BackgroundImageUploadedEvent,
                data, null, "FAILURE", "explicit-op");

        assertThat(event.getOutcome()).isEqualTo("FAILURE");
        assertThat(event.getOperationId()).isEqualTo("explicit-op");
        assertThat(event.getAuditEvent().getData()).isEqualTo(data);
    }
}