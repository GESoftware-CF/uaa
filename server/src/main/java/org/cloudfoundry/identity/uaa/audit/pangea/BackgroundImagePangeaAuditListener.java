package org.cloudfoundry.identity.uaa.audit.pangea;

import jakarta.annotation.PreDestroy;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.zone.event.BackgroundImageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Component
@ConditionalOnProperty(prefix = "pangea.audit", name = "enabled", havingValue = "true")
public class BackgroundImagePangeaAuditListener implements ApplicationListener<BackgroundImageEvent> {
    private static final Logger logger = LoggerFactory.getLogger(BackgroundImagePangeaAuditListener.class);
    private static final String UNKNOWN = "unknown";

    static final String ACTION_UPLOADED = "Background image uploaded";
    static final String ACTION_REPLACED = "Background image replaced";
    static final String ACTION_DELETED = "Background image deleted";
    static final String ACTION_UPLOAD_FAILED = "Background image upload failed";
    static final String ACTION_DELETE_FAILED = "Background image delete failed";

    private final PangeaAuditClient client;
    private final ThreadPoolExecutor executor;
    private final AtomicLong droppedEvents = new AtomicLong();

    @Autowired
    public BackgroundImagePangeaAuditListener(PangeaAuditClient client) {
        this(client, newExecutor());
    }

    BackgroundImagePangeaAuditListener(PangeaAuditClient client, ThreadPoolExecutor executor) {
        this.client = client;
        this.executor = executor;
    }

    @Override
    public void onApplicationEvent(BackgroundImageEvent event) {
        String zoneId = event == null ? UNKNOWN : value(event.getZoneId());
        String actionType = event == null ? UNKNOWN : actionType(event);
        try {
            if (event == null || UNKNOWN.equals(actionType)) {
                return;
            }
            // Actor and timestamp are captured on the request thread, before the hand-off.
            Actor actor = actor(event.getAuthentication());
            PangeaAuditClient.AuditMessage message = new PangeaAuditClient.AuditMessage(
                    actionType,
                    zoneId,
                    value(event.getOperationId()),
                    event.getData(),
                    actor.uuid(),
                    actor.name(),
                    actor.displayName(),
                    Instant.ofEpochMilli(event.getTimestamp()));
            executor.execute(() -> send(message, zoneId, actionType));
        } catch (Exception e) {
            warn(zoneId, actionType, event == null ? UNKNOWN : value(event.getOperationId()), reason(e),
                    e instanceof RejectedExecutionException);
        }
    }

    private void send(PangeaAuditClient.AuditMessage message, String zoneId, String actionType) {
        try {
            client.send(message);
        } catch (Exception e) {
            warn(zoneId, actionType, message.batchId(), reason(e), false);
        }
    }

    private static String actionType(BackgroundImageEvent event) {
        AuditEventType type = event.getType();
        if (type == null) {
            return UNKNOWN;
        }
        boolean failed = "FAILURE".equalsIgnoreCase(event.getOutcome());
        return switch (type) {
            case BackgroundImageUploadedEvent -> failed ? ACTION_UPLOAD_FAILED : ACTION_UPLOADED;
            case BackgroundImageReplacedEvent -> failed ? ACTION_UPLOAD_FAILED : ACTION_REPLACED;
            case BackgroundImageDeletedEvent -> failed ? ACTION_DELETE_FAILED : ACTION_DELETED;
            default -> UNKNOWN;
        };
    }

    private static Actor actor(Authentication authentication) {
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            return Actor.unknown();
        }
        if (authentication instanceof OAuth2Authentication oauth) {
            Authentication userAuthentication = oauth.getUserAuthentication();
            if (userAuthentication != null) {
                return actor(userAuthentication);
            }
            String clientId = value(oauth.getOAuth2Request().getClientId());
            return new Actor(clientId, clientId, clientId);
        }
        if (authentication instanceof UaaAuthentication uaa) {
            UaaPrincipal principal = uaa.getPrincipal();
            String name = value(principal.getName());
            return new Actor(value(principal.getId()), name, name);
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            String name = value(userDetails.getUsername());
            return new Actor(name, name, name);
        }
        String name = value(authentication.getName());
        return new Actor(name, name, name);
    }

    private static String value(String value) {
        return StringUtils.hasText(value) ? value : UNKNOWN;
    }

    private static String reason(Exception exception) {
        if (exception instanceof RejectedExecutionException) {
            return "QUEUE_FULL";
        }
        return exception instanceof PangeaAuditException pangeaException
                ? pangeaException.getReasonCode() : exception.getClass().getSimpleName();
    }

    private void warn(String zoneId, String actionType, String operationId, String reason, boolean dropped) {
        long droppedTotal = dropped ? droppedEvents.incrementAndGet() : droppedEvents.get();
        logger.warn("Pangea audit failed zoneId={} action_type={} op={} reason={} droppedEvents={}",
                zoneId, actionType, operationId, reason, droppedTotal);
    }

    private static ThreadPoolExecutor newExecutor() {
        AtomicInteger threadNumber = new AtomicInteger();
        ThreadFactory threadFactory = task -> {
            Thread thread = new Thread(task, "pangea-audit-" + threadNumber.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
        return new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(100), threadFactory, new ThreadPoolExecutor.AbortPolicy());
    }

    @PreDestroy
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private record Actor(String uuid, String name, String displayName) {
        private static Actor unknown() {
            return new Actor(UNKNOWN, UNKNOWN, UNKNOWN);
        }
    }
}