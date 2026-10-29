package org.cloudfoundry.identity.uaa.audit.pangea;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class PangeaAuditClientTest {
    private static final String AUDIT_URL = "https://pangea.example.test/v1/audit?source=uaa";
    private static final String VAULT_URL = "https://vault.example.test/v1/item";
    private static final String TOKEN = "pangea-secret-token";
    private static final String VAULT_TOKEN = "vault-auth-token";
    private static final String BODY_MARKER = "private-audit-payload";
    private static final String RESULT_URL = "https://pangea.example.test/v1/results/abc";
    private static final Instant EVENT_TIME = Instant.parse("2025-03-04T05:06:07.123Z");

    private RestTemplate restTemplate;
    private MockRestServiceServer server;
    private PangeaAuditProperties properties;
    private PangeaAuditClient client;
    private MutableClock clock;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.createServer(restTemplate);
        clock = new MutableClock(EVENT_TIME);
        properties = properties();
        client = client();
    }

    @Test
    void sendsExactEndpointHeadersAndBodyWithSuppliedUtcEventTime() {
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(content().string(not(containsString(TOKEN))))
                .andExpect(jsonPath("$.config_id").value("config-123"))
                .andExpect(jsonPath("$.verbose").value(false))
                .andExpect(jsonPath("$.event.action_type").value("Background image uploaded"))
                .andExpect(jsonPath("$.event.originator").value("BackgroundImageService"))
                .andExpect(jsonPath("$.event.tenant_id").value("zone-1"))
                .andExpect(jsonPath("$.event.actor_uuid").value("user-uuid"))
                .andExpect(jsonPath("$.event.resource").value("zone-background-image"))
                .andExpect(jsonPath("$.event.resource_uuid").value("zone-1"))
                .andExpect(jsonPath("$.event.batch_id").value("op-1"))
                .andExpect(jsonPath("$.event.actor_name").value("alice"))
                .andExpect(jsonPath("$.event.actor_display_name").value("Alice"))
                .andExpect(jsonPath("$.event.description").value(BODY_MARKER))
                .andExpect(jsonPath("$.event.app_name").value("uaa"))
                .andExpect(jsonPath("$.event.event_time").value("2025-03-04T05:06:07.123Z"))
                .andRespond(withSuccess());

        client.send(message());

        server.verify();
        assertThat(properties.toString()).doesNotContain(TOKEN, VAULT_TOKEN);
    }

    @Test
    void acceptsPostStatus200() {
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST)).andRespond(withSuccess());

        client.send(message());

        server.verify();
    }

    @Test
    void pollsResultAfterPostStatus202UntilStatus200() {
        acceptedPost(RESULT_URL);
        server.expect(requestTo(RESULT_URL)).andExpect(method(GET))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN))
                .andRespond(withSuccess());

        client.send(message());

        server.verify();
    }

    @Test
    void pollExhaustionDoesNotRepostAcceptedEvent() {
        properties.setRetryCounter(2);
        properties.setRetryIntervalMs(1);
        acceptedPost(RESULT_URL);
        server.expect(ExpectedCount.times(2), requestTo(RESULT_URL)).andExpect(method(GET))
                .andRespond(withStatus(HttpStatus.ACCEPTED));

        assertFailure(() -> client.send(message()), "POLL_EXHAUSTED");

        server.verify();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://pangea.example.test/v1/results/abc",
            "https://other.example.test/v1/results/abc"})
    void rejectsUntrustedPollLocationWithoutSendingAnotherRequest(String location) {
        acceptedPost(location);

        assertFailure(() -> client.send(message()), "BAD_LOCATION");

        server.verify();
    }

    @Test
    void invalidatesVaultTokenAndRetriesPostOnceAfter401() {
        configureVault();
        // Calls happen in this order: vault fetch, audit POST (401), vault fetch, audit POST (200).
        server.expect(requestTo(VAULT_URL)).andExpect(method(POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + VAULT_TOKEN))
                .andExpect(jsonPath("$.id").value("vault-item-id"))
                .andRespond(vaultToken("old-pangea-token"));
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer old-pangea-token"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        server.expect(requestTo(VAULT_URL)).andExpect(method(POST))
                .andRespond(vaultToken("new-pangea-token"));
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer new-pangea-token"))
                .andRespond(withSuccess());

        client.send(message());

        server.verify();
    }

    @Test
    void staticTokenIs401IsNotRetried() {
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED).body(BODY_MARKER));

        assertFailure(() -> client.send(message()), "HTTP_401");

        server.verify();
    }

    @Test
    void retriesPostOn503ThenSucceeds() {
        properties.setRetryIntervalMs(1);
        server.expect(requestTo(AUDIT_URL)).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE)
                .body(BODY_MARKER));
        server.expect(requestTo(AUDIT_URL)).andRespond(withSuccess());

        client.send(message());

        server.verify();
    }

    @Test
    void retriesPostTimeoutAtMostThreeTimes() {
        properties.setRetryIntervalMs(1);
        server.expect(ExpectedCount.times(3), requestTo(AUDIT_URL)).andRespond(request -> {
            throw new IOException("transport", new SocketTimeoutException(BODY_MARKER));
        });

        assertFailure(() -> client.send(message()), "TIMEOUT");

        server.verify();
    }

    @Test
    void pollTimeoutIsNotRetriedAsPost() {
        acceptedPost(RESULT_URL);
        server.expect(requestTo(RESULT_URL)).andExpect(method(GET)).andRespond(request -> {
            throw new IOException("transport", new SocketTimeoutException(BODY_MARKER));
        });

        assertFailure(() -> client.send(message()), "TIMEOUT");

        server.verify();
    }

    @Test
    void doesNotRetry4xx() {
        server.expect(requestTo(AUDIT_URL)).andRespond(withStatus(HttpStatus.BAD_REQUEST).body(BODY_MARKER));

        assertFailure(() -> client.send(message()), "HTTP_400");

        server.verify();
    }

    @Test
    void retriesTransientPostFailuresAtMostThreeTimes() {
        properties.setRetryIntervalMs(1);
        server.expect(ExpectedCount.times(3), requestTo(AUDIT_URL))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertFailure(() -> client.send(message()), "HTTP_503");

        server.verify();
    }

    @Test
    void vaultTokenFetchIsCachedAndRefreshedAfterConfiguredAge() {
        configureVault();
        properties.setVaultTokenRefreshMinutes(1);
        // Order: vault fetch, audit, audit (cached token), vault fetch (after expiry), audit.
        server.expect(requestTo(VAULT_URL)).andRespond(vaultToken("first-token"));
        server.expect(requestTo(AUDIT_URL))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer first-token"))
                .andRespond(withSuccess());
        server.expect(requestTo(AUDIT_URL))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer first-token"))
                .andRespond(withSuccess());
        server.expect(requestTo(VAULT_URL)).andRespond(vaultToken("second-token"));
        server.expect(requestTo(AUDIT_URL))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer second-token"))
                .andRespond(withSuccess());

        client.send(message());
        client.send(message());
        clock.advanceSeconds(61);
        client.send(message());

        server.verify();
    }

    @Test
    void vault4xxFailsImmediatelyWithoutExposingSecrets() {
        configureVault();
        server.expect(requestTo(VAULT_URL)).andRespond(withStatus(HttpStatus.BAD_REQUEST)
                .body(BODY_MARKER + ' ' + VAULT_TOKEN));

        assertThatThrownBy(() -> client.send(message()))
                .isInstanceOf(PangeaAuditException.class)
                .hasMessageNotContainingAny(BODY_MARKER, VAULT_TOKEN)
                .satisfies(error -> assertThat(((PangeaAuditException) error).getReasonCode()).isEqualTo("HTTP_400"));

        server.verify();
    }

    @Test
    void vault5xxRetriesUpToRetryCounter() {
        configureVault();
        properties.setRetryCounter(2);
        properties.setRetryIntervalMs(1);
        server.expect(requestTo(VAULT_URL)).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(VAULT_URL)).andRespond(vaultToken("pangea-token"));
        server.expect(requestTo(AUDIT_URL))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer pangea-token"))
                .andRespond(withSuccess());

        client.send(message());

        server.verify();
    }

    private void acceptedPost(String location) {
        server.expect(requestTo(AUDIT_URL)).andExpect(method(POST))
                .andRespond(withStatus(HttpStatus.ACCEPTED).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"result\":{\"location\":\"" + location + "\"}}"));
    }

    private static ResponseCreator vaultToken(String token) {
        return withSuccess("{\"result\":{\"item_versions\":[{\"token\":\"" + token + "\"}]}}",
                MediaType.APPLICATION_JSON);
    }

    private static PangeaAuditProperties properties() {
        PangeaAuditProperties properties = new PangeaAuditProperties();
        properties.setEnabled(true);
        properties.setUrl(AUDIT_URL);
        properties.setConfigId("config-123");
        properties.setToken(TOKEN);
        properties.setRetryCounter(5);
        return properties;
    }

    /** Switches to Vault mode and rebuilds the client, since the token mode is decided at construction. */
    private void configureVault() {
        properties.setToken("");
        properties.setVaultUri(VAULT_URL);
        properties.setVaultToken(VAULT_TOKEN);
        properties.setVaultTokenId("vault-item-id");
        client = client();
    }

    private PangeaAuditClient client() {
        return new PangeaAuditClient(properties, restTemplate, clock);
    }

    private static PangeaAuditClient.AuditMessage message() {
        return new PangeaAuditClient.AuditMessage("Background image uploaded", "zone-1", "op-1",
                BODY_MARKER, "user-uuid", "alice", "Alice", EVENT_TIME);
    }

    private static void assertFailure(Runnable action, String reason) {
        assertThatThrownBy(action::run)
                .isInstanceOf(PangeaAuditException.class)
                .hasMessageNotContainingAny(TOKEN, VAULT_TOKEN, BODY_MARKER)
                .satisfies(error -> assertThat(((PangeaAuditException) error).getReasonCode()).isEqualTo(reason));
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> instant;

        private MutableClock(Instant initial) {
            instant = new AtomicReference<>(initial);
        }

        private void advanceSeconds(long seconds) {
            instant.updateAndGet(current -> current.plusSeconds(seconds));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}