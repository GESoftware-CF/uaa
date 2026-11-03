package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcUnsuccessfulLoginCountingAuditService;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AuditListener;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class BackgroundImageEventTest {
    @Test
    void shouldCreateAuditRecordWithTargetZoneAndPassedData() {
        String zoneId = "target-zone";
        String data = "outcome=SUCCESS; op=operation";
        var event = new BackgroundImageEvent(zoneId, AuditEventType.BackgroundImageUploadedEvent,
            data, null);

        AuditEvent audit = event.getAuditEvent();

        assertThat(audit.getType()).isEqualTo(AuditEventType.BackgroundImageUploadedEvent);
        assertThat(audit.getPrincipalId()).isEqualTo(zoneId);
        assertThat(audit.getIdentityZoneId()).isEqualTo(zoneId);
        assertThat(audit.getData()).isEqualTo(data);
        assertThat(audit.getOrigin()).isNull();
        assertThatCode(event::getAuditEvent).doesNotThrowAnyException();
    }

    @Test
    void shouldPreserveFailureDataInAuditRecord() {
        String data = "outcome=FAILURE; op=operation-2; stage=dbUpdate";
        var event = new BackgroundImageEvent("target-zone", AuditEventType.BackgroundImageDeletedEvent,
            data, null);

        assertThat(event.getIdentityZoneId()).isEqualTo("target-zone");
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.BackgroundImageDeletedEvent);
        assertThat(event.getAuditEvent().getData()).isEqualTo(data);
    }

    @ParameterizedTest
    @EnumSource(value = AuditEventType.class,
            names = {"BackgroundImageUploadedEvent", "BackgroundImageDeletedEvent"})
    void shouldLogAuditRecordThroughRealListenerWhenBackgroundImageEventArrives(AuditEventType type) {
        String zoneId = "target-zone";
        String data = "outcome=SUCCESS; op=operation";
        Logger logger = mock(Logger.class);
        LoggingAuditService service = spy(new LoggingAuditService());
        service.setLogger(logger);
        AuditListener listener = new AuditListener(service);
        var event = new BackgroundImageEvent(zoneId, type, data, null);

        listener.onApplicationEvent(event);

        ArgumentCaptor<AuditEvent> record = ArgumentCaptor.forClass(AuditEvent.class);
        verify(service).log(record.capture(), eq(zoneId));
        assertThat(record.getValue().getType()).isEqualTo(type);
        assertThat(record.getValue().getPrincipalId()).isEqualTo(zoneId);
        assertThat(record.getValue().getIdentityZoneId()).isEqualTo(zoneId);
        assertThat(record.getValue().getData()).isEqualTo(data);
        verify(logger).info(type.name() + " ('" + data + "'): principal=" + zoneId
                + ", origin=[null], identityZoneId=[" + zoneId + "]");
    }

    @ParameterizedTest
    @EnumSource(value = AuditEventType.class,
            names = {"BackgroundImageUploadedEvent", "BackgroundImageDeletedEvent"})
    void shouldRequestJdbcInsertForBackgroundImageEvents(AuditEventType type) {
        String zoneId = "target-zone";
        JdbcTemplate template = mock(JdbcTemplate.class);
        AuditListener listener = new AuditListener(
                new JdbcUnsuccessfulLoginCountingAuditService(template, mock(TimeService.class)));

        for (String outcome : new String[]{"SUCCESS", "FAILURE"}) {
            String data = "outcome=" + outcome + "; op=operation";
            listener.onApplicationEvent(new BackgroundImageEvent(zoneId, type, data, null));

            verify(template).update("insert into sec_audit (principal_id, event_type, origin, event_data, identity_zone_id) values (?,?,?,?,?)",
                    zoneId, type.getCode(), "", data, zoneId);
        }
    }
}