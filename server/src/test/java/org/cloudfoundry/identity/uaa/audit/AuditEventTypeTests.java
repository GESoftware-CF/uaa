package org.cloudfoundry.identity.uaa.audit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuditEventTypeTests {

    @Test
    void auditEventType() {
        int count = 0;
        for (AuditEventType type : AuditEventType.values()) {
            assertThat(type.getCode()).isEqualTo(count);
            assertThat(AuditEventType.fromCode(count)).isEqualTo(type);
            count++;
        }
        assertThat(AuditEventType.BackgroundImageUploadedEvent.getCode()).isEqualTo(43);
        assertThat(AuditEventType.BackgroundImageReplacedEvent.getCode()).isEqualTo(44);
        assertThat(AuditEventType.BackgroundImageDeletedEvent.getCode()).isEqualTo(45);
    }
}
