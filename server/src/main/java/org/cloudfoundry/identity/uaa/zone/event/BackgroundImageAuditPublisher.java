package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/** Publishes sanitized background-image audit events through UAA's application event bus. */
@Component
public class BackgroundImageAuditPublisher implements ApplicationEventPublisherAware {
    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageAuditPublisher.class);
    /** Keeps replacement and failure details intact in the audit event payload. */
    private static final int MAX_DATA_LENGTH = 512;

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void uploaded(String zoneId, String subdomain, String operationId,
                         String object, long sizeBytes, String contentType) {
        publish(AuditEventType.BackgroundImageUploadedEvent, zoneId, success(operationId, subdomain, object,
            null, null, null, sizeBytes, contentType), "SUCCESS", operationId);
    }

    public void replaced(String zoneId, String subdomain, String operationId,
                         String object, String previousObject, boolean previousDeleted,
                         long sizeBytes, String contentType) {
        publish(AuditEventType.BackgroundImageReplacedEvent, zoneId, success(operationId, subdomain, object,
            previousObject, previousDeleted, null, sizeBytes, contentType), "SUCCESS", operationId);
    }

    public void deleted(String zoneId, String subdomain, String operationId, String object, boolean s3Deleted) {
        publish(AuditEventType.BackgroundImageDeletedEvent, zoneId,
            success(operationId, subdomain, object, null, null, s3Deleted, null, null), "SUCCESS", operationId);
    }

    public void failed(AuditEventType type, String zoneId, String subdomain, String operationId,
                       String object, long sizeBytes, String contentType, String stage, Exception cause) {
        publish(type, zoneId, data("FAILURE", operationId, subdomain, object, null, null, null,
            sizeBytes, contentType, stage, cause == null ? null : cause.getClass().getSimpleName()),
            "FAILURE", operationId);
    }

    private static String success(String operationId, String subdomain, String object,
                                  String previousObject, Boolean previousDeleted, Boolean s3Deleted,
                                  Long sizeBytes, String contentType) {
        return data("SUCCESS", operationId, subdomain, object, previousObject, previousDeleted, s3Deleted,
                sizeBytes, contentType, null, null);
    }

    private static String data(String outcome, String operationId, String subdomain, String object,
                               String previousObject, Boolean previousDeleted, Boolean s3Deleted,
                               Long sizeBytes, String contentType, String stage, String reason) {
        StringBuilder data = new StringBuilder(192)
                .append("outcome=").append(value(outcome))
                .append("; op=").append(value(operationId))
                .append("; subdomain=").append(value(subdomain))
                .append("; object=").append(value(object));
        if (previousObject != null || previousDeleted != null) {
            data.append("; previous=").append(value(previousObject))
                    .append("; previousDeleted=").append(previousDeleted != null && previousDeleted);
        }
        if (s3Deleted != null) {
            data.append("; s3Deleted=").append(s3Deleted);
        }
        if (sizeBytes != null) {
            data.append("; sizeBytes=").append(sizeBytes);
        }
        if (contentType != null) {
            data.append("; contentType=").append(value(contentType));
        }
        if (stage != null || reason != null) {
            data.append("; stage=").append(value(stage))
                    .append("; reason=").append(value(reason));
        }
        return data.length() > MAX_DATA_LENGTH ? data.substring(0, MAX_DATA_LENGTH) : data.toString();
    }

    private static String value(String value) {
        if (value == null) {
            return "-";
        }
        return value.replace(';', '_').replace('\r', '_').replace('\n', '_');
    }

    private void publish(AuditEventType type, String zoneId, String data, String outcome, String operationId) {
        try {
            if (publisher != null) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                publisher.publishEvent(new BackgroundImageEvent(zoneId, type, data, authentication, outcome, operationId));
            }
        } catch (RuntimeException e) {
            logger.warn("zoneId={} outcome=audit-publish-failed type={}", value(zoneId), type, e);
        }
    }
}