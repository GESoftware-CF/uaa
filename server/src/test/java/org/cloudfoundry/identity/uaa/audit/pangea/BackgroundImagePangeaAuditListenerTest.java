package org.cloudfoundry.identity.uaa.audit.pangea;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.LoggerContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.zone.event.BackgroundImageEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Instant;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class BackgroundImagePangeaAuditListenerTest {
    private static final String ZONE_ID = "zone-1";
    private static final String TOKEN_MARKER = "do-not-log-token";
    private static final String PAYLOAD_MARKER = "do-not-log-payload";

    private BackgroundImagePangeaAuditListener listener;
    private ThreadPoolExecutor executor;

    @AfterEach
    void shutDownExecutor() {
        if (listener != null) {
            listener.shutdown();
        }
    }

    @ParameterizedTest
    @MethodSource("backgroundImageTypes")
    void mapsSuccessfulEventsToPangeaFields(AuditEventType type, String actionType) throws Exception {
        PangeaAuditClient client = mock(PangeaAuditClient.class);
        executor = executor(2, 10);
        listener = new BackgroundImagePangeaAuditListener(client, executor);
        CountDownLatch delivered = new CountDownLatch(1);
        AtomicReference<PangeaAuditClient.AuditMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            delivered.countDown();
            return null;
        }).when(client).send(any());

        BackgroundImageEvent event = event(type, userAuthentication(), "SUCCESS");
        Instant eventTime = Instant.ofEpochMilli(event.getTimestamp());
        listener.onApplicationEvent(event);

        assertTrue(delivered.await(1, TimeUnit.SECONDS));
        PangeaAuditClient.AuditMessage message = captured.get();
        assertThat(message.actionType()).isEqualTo(actionType);
        assertThat(message.zoneId()).isEqualTo(ZONE_ID);
        assertThat(message.batchId()).isEqualTo("op-42");
        assertThat(message.description()).isEqualTo("outcome=SUCCESS; op=op-42; stage=dbUpdate");
        assertThat(message.actorUuid()).isEqualTo("user-uuid");
        assertThat(message.actorName()).isEqualTo("alice");
        assertThat(message.actorDisplayName()).isEqualTo("alice");
        assertThat(message.eventTime()).isEqualTo(eventTime);
        verify(client).send(message);
    }

    @ParameterizedTest
    @MethodSource("failureImageTypes")
    void mapsFailureOutcomesToFailureActionTypes(AuditEventType type, String expectedAction) throws Exception {
        PangeaAuditClient client = mock(PangeaAuditClient.class);
        executor = executor(1, 2);
        listener = new BackgroundImagePangeaAuditListener(client, executor);
        CountDownLatch delivered = new CountDownLatch(1);
        AtomicReference<PangeaAuditClient.AuditMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            delivered.countDown();
            return null;
        }).when(client).send(any());

        listener.onApplicationEvent(event(type, userAuthentication(), "FAILURE"));

        assertTrue(delivered.await(1, TimeUnit.SECONDS));
        assertThat(captured.get().actionType()).isEqualTo(expectedAction);
        assertThat(captured.get().description()).isEqualTo("outcome=FAILURE; op=op-42; stage=dbUpdate");
    }

    @Test
    void usesClientIdForClientAuthenticationAndUnknownWhenAbsent() throws Exception {
        PangeaAuditClient client = mock(PangeaAuditClient.class);
        executor = executor(1, 4);
        listener = new BackgroundImagePangeaAuditListener(client, executor);
        CountDownLatch delivered = new CountDownLatch(2);
        List<PangeaAuditClient.AuditMessage> messages = new ArrayList<>();
        doAnswer(invocation -> {
            messages.add(invocation.getArgument(0));
            delivered.countDown();
            return null;
        }).when(client).send(any());

        OAuth2Request request = new OAuth2Request(Map.of(), "client-123", List.of(), true, Set.of(), Set.of(),
                null, Set.of(), Map.of());
        listener.onApplicationEvent(event(AuditEventType.BackgroundImageUploadedEvent,
                new OAuth2Authentication(request, null)));
        listener.onApplicationEvent(event(AuditEventType.BackgroundImageDeletedEvent, null));

        assertTrue(delivered.await(1, TimeUnit.SECONDS));
        assertThat(messages).hasSize(2);
        assertThat(messages.get(0).actorUuid()).isEqualTo("client-123");
        assertThat(messages.get(0).actorName()).isEqualTo("client-123");
        assertThat(messages.get(0).actorDisplayName()).isEqualTo("client-123");
        assertThat(messages.get(1).actorUuid()).isEqualTo("unknown");
        assertThat(messages.get(1).actorName()).isEqualTo("unknown");
        assertThat(messages.get(1).actorDisplayName()).isEqualTo("unknown");
    }

    @Test
    void doesNotWaitForSlowClientDropsWhenQueueIsFullAndLogsNoPayloadOrToken() throws Exception {
        PangeaAuditClient client = mock(PangeaAuditClient.class);
        executor = executor(1, 1);
        listener = new BackgroundImagePangeaAuditListener(client, executor);
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch completed = new CountDownLatch(2);
        AtomicInteger callCount = new AtomicInteger();
        doAnswer(invocation -> {
            try {
                if (callCount.incrementAndGet() == 1) {
                    firstStarted.countDown();
                    release.await(2, TimeUnit.SECONDS);
                }
                throw new IllegalStateException(TOKEN_MARKER + ' ' + PAYLOAD_MARKER);
            } finally {
                completed.countDown();
            }
        }).when(client).send(any());

        CapturingAppender appender = attachAppender(Level.WARN, 3);
        try {
            assertThatCode(() -> listener.onApplicationEvent(event(
                    AuditEventType.BackgroundImageUploadedEvent, userAuthentication()))).doesNotThrowAnyException();
            assertTrue(firstStarted.await(1, TimeUnit.SECONDS));
            assertThatCode(() -> listener.onApplicationEvent(event(
                    AuditEventType.BackgroundImageReplacedEvent, userAuthentication()))).doesNotThrowAnyException();
            assertThat(executor.getQueue()).hasSize(1);

            long start = System.nanoTime();
            assertThatCode(() -> listener.onApplicationEvent(event(
                    AuditEventType.BackgroundImageDeletedEvent, userAuthentication()))).doesNotThrowAnyException();
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertThat(elapsedMillis).isLessThan(250);

            release.countDown();
            assertTrue(completed.await(2, TimeUnit.SECONDS));
            assertTrue(appender.await(1, TimeUnit.SECONDS));
            List<String> messages = appender.messages();
            assertThat(messages).hasSize(3);
            assertThat(messages).allSatisfy(message -> {
                assertThat(message).contains("zoneId=" + ZONE_ID, "action_type=", "reason=")
                        .contains("droppedEvents=1")
                        .doesNotContain(TOKEN_MARKER, PAYLOAD_MARKER);
            });
            assertThat(messages).anyMatch(message -> message.contains("reason=QUEUE_FULL"));
        } finally {
            release.countDown();
            detachAppender(appender);
        }
    }

    @Test
    void logsOnlySafeReasonWhenClientFails() throws Exception {
        PangeaAuditClient client = mock(PangeaAuditClient.class);
        executor = executor(1, 2);
        listener = new BackgroundImagePangeaAuditListener(client, executor);
        CapturingAppender appender = attachAppender(Level.WARN, 1);
        doAnswer(invocation -> {
            throw new PangeaAuditException("HTTP_401", new IllegalStateException(TOKEN_MARKER + PAYLOAD_MARKER));
        }).when(client).send(any());
        try {
            listener.onApplicationEvent(event(AuditEventType.BackgroundImageUploadedEvent,
                    userAuthentication(), "SUCCESS"));
            assertTrue(appender.await(1, TimeUnit.SECONDS));
            assertThat(appender.messages()).hasSize(1).allSatisfy(message ->
                    assertThat(message).contains("reason=HTTP_401").doesNotContain(TOKEN_MARKER, PAYLOAD_MARKER));
        } finally {
            detachAppender(appender);
        }
    }

    private static Stream<Arguments> backgroundImageTypes() {
        return Stream.of(
                Arguments.of(AuditEventType.BackgroundImageUploadedEvent, "BACKGROUND_IMAGE_UPLOADED"),
                Arguments.of(AuditEventType.BackgroundImageReplacedEvent, "BACKGROUND_IMAGE_REPLACED"),
                Arguments.of(AuditEventType.BackgroundImageDeletedEvent, "BACKGROUND_IMAGE_DELETED"));
    }

    private static Stream<Arguments> failureImageTypes() {
        return Stream.of(
                Arguments.of(AuditEventType.BackgroundImageUploadedEvent, "BACKGROUND_IMAGE_UPLOAD_FAILED"),
                Arguments.of(AuditEventType.BackgroundImageReplacedEvent, "BACKGROUND_IMAGE_UPLOAD_FAILED"),
                Arguments.of(AuditEventType.BackgroundImageDeletedEvent, "BACKGROUND_IMAGE_DELETE_FAILED"));
    }

    private static BackgroundImageEvent event(AuditEventType type, Authentication authentication) {
        return event(type, authentication, "SUCCESS");
    }

    private static BackgroundImageEvent event(AuditEventType type, Authentication authentication, String outcome) {
        return new BackgroundImageEvent(ZONE_ID, type,
                "outcome=" + outcome + "; op=op-42; stage=dbUpdate", authentication, outcome, "op-42");
    }

    private static UaaAuthentication userAuthentication() {
        return new UaaAuthentication(new UaaPrincipal("user-uuid", "alice", null, "uaa", null, ZONE_ID),
                List.of(), null);
    }

    private static ThreadPoolExecutor executor(int threads, int queueSize) {
        return new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueSize));
    }

    private static CapturingAppender attachAppender(Level level, int expectedEvents) {
        CapturingAppender appender = new CapturingAppender("pangea-test-" + UUID.randomUUID(), expectedEvents);
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        LoggerConfig loggerConfig = context.getConfiguration().getLoggerConfig(
                BackgroundImagePangeaAuditListener.class.getName());
        appender.start();
        loggerConfig.addAppender(appender, level, null);
        context.updateLoggers();
        return appender;
    }

    private static void detachAppender(CapturingAppender appender) {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        LoggerConfig loggerConfig = context.getConfiguration().getLoggerConfig(
                BackgroundImagePangeaAuditListener.class.getName());
        loggerConfig.removeAppender(appender.getName());
        context.updateLoggers();
        appender.stop();
    }

    private static final class CapturingAppender extends AbstractAppender {
        private final List<LogEvent> events = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final CountDownLatch expectedEvents;

        private CapturingAppender(String name, int expectedEventCount) {
            super(name, null, null, true, new Property[0]);
            expectedEvents = new CountDownLatch(expectedEventCount);
        }

        @Override
        public void append(LogEvent event) {
            events.add(event.toImmutable());
            expectedEvents.countDown();
        }

        private boolean await(long timeout, TimeUnit unit) throws InterruptedException {
            return expectedEvents.await(timeout, unit);
        }

        private List<String> messages() {
            return events.stream().map(event -> event.getMessage().getFormattedMessage()).toList();
        }
    }
}