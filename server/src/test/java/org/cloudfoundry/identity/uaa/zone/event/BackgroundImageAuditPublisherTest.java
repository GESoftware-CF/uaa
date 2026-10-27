package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BackgroundImageAuditPublisherTest {
    @Mock private ApplicationEventPublisher applicationEventPublisher;
    private BackgroundImageAuditPublisher publisher;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        publisher = new BackgroundImageAuditPublisher();
        publisher.setApplicationEventPublisher(applicationEventPublisher);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldPublishUploadEvent() {
        publisher.uploaded("zone1", "subdomain", "op-1", "zone1/file.png", 123, "image/png");

        BackgroundImageEvent event = captureEvent();
        assertThat(event.getOutcome()).isEqualTo("SUCCESS");
        assertThat(event.getOperationId()).isEqualTo("op-1");
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.BackgroundImageUploadedEvent);
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo("zone1");
        assertThat(event.getAuditEvent().getIdentityZoneId()).isEqualTo("zone1");
        assertThat(event.getAuditEvent().getOrigin()).isNull();
        assertThat(event.getAuditEvent().getData()).isEqualTo(
                "outcome=SUCCESS; op=op-1; subdomain=subdomain; object=zone1/file.png; sizeBytes=123; contentType=image/png");
    }

    @Test
    void shouldPublishReplacementAndPreviousDeleteOutcome() {
        publisher.replaced("zone1", "subdomain", "op-2", "zone1/new.jpg", "zone1/old.jpg", false,
                456, "image/jpeg");

        BackgroundImageEvent event = captureEvent();
        var data = event.getAuditEvent().getData();
        assertThat(data).contains("outcome=SUCCESS", "object=zone1/new.jpg", "previous=zone1/old.jpg",
                "previousDeleted=false", "sizeBytes=456", "contentType=image/jpeg");
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.BackgroundImageReplacedEvent);
    }

    @Test
    void shouldPublishDeleteWithS3Outcome() {
        publisher.deleted("zone1", "subdomain", "op-3", "zone1/old.jpg", false);

        BackgroundImageEvent event = captureEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.BackgroundImageDeletedEvent);
        assertThat(event.getAuditEvent().getData()).contains("outcome=SUCCESS", "s3Deleted=false")
            .doesNotContain("sizeBytes=", "contentType=");
    }

    @Test
    void shouldPublishFailureWithoutExceptionMessage() {
        publisher.failed(AuditEventType.BackgroundImageUploadedEvent, "zone1", "subdomain", "op-4",
                "zone1/file.png", 123, "image/png", "s3Upload",
                new IllegalStateException("secret message must not be logged into audit data"));

        var event = captureEvent();
        assertThat(event.getOutcome()).isEqualTo("FAILURE");
        assertThat(event.getOperationId()).isEqualTo("op-4");
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.BackgroundImageUploadedEvent);
        assertThat(event.getAuditEvent().getData()).contains("outcome=FAILURE", "stage=s3Upload",
                "reason=IllegalStateException").doesNotContain("secret message");
    }

    @Test
    void shouldNeutralizeDelimitersAndNewlines() {
        publisher.uploaded("zone;1", "sub\ndomain", "op", "zone1/file;forged=yes\n", 1, "image/png");

        String data = captureEvent().getAuditEvent().getData();
        assertThat(data).doesNotContain("\n", "\r", "file;forged")
                .contains("sub_domain", "zone1/file_forged=yes_");
    }

    @Test
    void shouldTruncateAuditDataTo512Characters() {
        String longSubdomain = "s".repeat(600);
        publisher.uploaded("zone1", longSubdomain, "op", "zone1/file.jpg", 1, "image/jpeg");

        assertThat(captureEvent().getAuditEvent().getData()).hasSize(512);
    }

    @Test
    void replacementWithMaximumIdentifiersRetainsAllOperationalFields() {
        String zoneId = "z".repeat(36);
        String subdomain = "s".repeat(20);
        String operationId = "o".repeat(36);
        String object = zoneId + "/1792741732107-93b11922.jpg";

        publisher.replaced(zoneId, subdomain, operationId, object, object, false, 1234567, "image/jpeg");

        String data = captureEvent().getAuditEvent().getData();
        assertThat(data).hasSize(300).contains("previousDeleted=false", "sizeBytes=1234567", "contentType=image/jpeg");
    }

    @Test
    void shouldNotThrowWhenApplicationPublisherIsAbsent() {
        var publisherWithoutContext = new BackgroundImageAuditPublisher();
        assertThatCode(() -> {
            publisherWithoutContext.uploaded("zone1", null, "op", "zone1/file.png", 1, "image/png");
            publisherWithoutContext.replaced("zone1", null, "op", "zone1/new.png", "zone1/old.png",
                false, 1, "image/png");
            publisherWithoutContext.deleted("zone1", null, "op", "zone1/old.png", false);
            publisherWithoutContext.failed(AuditEventType.BackgroundImageDeletedEvent, "zone1", null, "op",
                "zone1/old.png", 0, "-", "dbUpdate", new IllegalStateException("secret"));
        })
                .doesNotThrowAnyException();
    }

    @Test
    void shouldNotThrowWhenApplicationPublisherThrows() {
        doThrow(new IllegalStateException("internal publisher failure"))
                .when(applicationEventPublisher).publishEvent(org.mockito.ArgumentMatchers.any(ApplicationEvent.class));

        assertThatCode(() -> publisher.uploaded("zone1", "subdomain", "op", "zone1/file.png", 1, "image/png"))
                .doesNotThrowAnyException();
    }

    private BackgroundImageEvent captureEvent() {
        ArgumentCaptor<ApplicationEvent> captor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(applicationEventPublisher).publishEvent(captor.capture());
        return (BackgroundImageEvent) captor.getValue();
    }

}