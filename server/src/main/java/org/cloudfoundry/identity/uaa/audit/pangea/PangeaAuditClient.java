package org.cloudfoundry.identity.uaa.audit.pangea;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

@Component
@ConditionalOnProperty(prefix = "pangea.audit", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(PangeaAuditProperties.class)
public class PangeaAuditClient {
    private static final Logger logger = LoggerFactory.getLogger(PangeaAuditClient.class);
    private static final DateTimeFormatter EVENT_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final String ORIGINATOR = "BackgroundImageService";
    private static final int MAX_POST_ATTEMPTS = 3;

    private final PangeaAuditProperties properties;
    private final RestTemplate restTemplate;
    private final TokenHolder tokenHolder;

    @Autowired
    public PangeaAuditClient(PangeaAuditProperties properties) {
        this(properties, createRestTemplate(properties), Clock.systemUTC());
    }

    PangeaAuditClient(PangeaAuditProperties properties, RestTemplate restTemplate, Clock clock) {
        this.properties = properties;
        this.restTemplate = restTemplate;
        this.tokenHolder = new TokenHolder(properties, restTemplate, clock);
    }

    public void send(AuditMessage message) {
        PostResult result = postWithRetry(message);
        int status = result.response().getStatusCode().value();
        if (status == 200) {
            logSuccess(message, result.attempt());
            return;
        }
        if (status == 202) {
            pollResult(result.response().getBody());
            logSuccess(message, result.attempt());
            return;
        }
        throw new PangeaAuditException("HTTP_" + status);
    }

    private PostResult postWithRetry(AuditMessage message) {
        int attempt = 0;
        int transientFailures = 0;
        boolean unauthorizedRetried = false;
        while (true) {
            attempt++;
            String token = tokenHolder.get();
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody(message), headers(token));
            try {
                ResponseEntity<JsonNode> response = restTemplate.postForEntity(
                        URI.create(properties.getUrl()), request, JsonNode.class);
                return new PostResult(response, attempt);
            } catch (HttpStatusCodeException e) {
                int status = e.getStatusCode().value();
                // A rotated Vault token is the only case where retrying a 401 can help.
                if (status == 401 && tokenHolder.isVault() && !unauthorizedRetried) {
                    tokenHolder.invalidate();
                    unauthorizedRetried = true;
                    continue;
                }
                if (status >= 500 && transientFailures < MAX_POST_ATTEMPTS - 1) {
                    sleepBeforePostRetry(transientFailures++);
                    continue;
                }
                throw new PangeaAuditException("HTTP_" + status, e);
            } catch (ResourceAccessException e) {
                if (transientFailures < MAX_POST_ATTEMPTS - 1) {
                    sleepBeforePostRetry(transientFailures++);
                    continue;
                }
                throw new PangeaAuditException(isTimeout(e) ? "TIMEOUT" : "CONNECTION_ERROR", e);
            } catch (PangeaAuditException e) {
                throw e;
            } catch (Exception e) {
                throw new PangeaAuditException("INVALID_RESPONSE", e);
            }
        }
    }

    private void pollResult(JsonNode responseBody) {
        URI location = validateLocation(resultLocation(responseBody));
        HttpEntity<Void> request = new HttpEntity<>(headers(tokenHolder.get()));
        for (int attempt = 0; attempt < properties.getRetryCounter(); attempt++) {
            try {
                ResponseEntity<JsonNode> response = restTemplate.exchange(location, HttpMethod.GET, request,
                        JsonNode.class);
                int status = response.getStatusCode().value();
                if (status == 200) {
                    return;
                }
                if (status != 202) {
                    throw new PangeaAuditException("HTTP_" + status);
                }
                if (attempt + 1 < properties.getRetryCounter()) {
                    sleep(properties.getRetryIntervalMs());
                }
            } catch (HttpStatusCodeException e) {
                throw new PangeaAuditException("HTTP_" + e.getStatusCode().value(), e);
            } catch (ResourceAccessException e) {
                throw new PangeaAuditException(isTimeout(e) ? "TIMEOUT" : "CONNECTION_ERROR", e);
            }
        }
        throw new PangeaAuditException("POLL_EXHAUSTED");
    }

    private void sleepBeforePostRetry(int retryIndex) {
        sleep(properties.getRetryIntervalMs() << retryIndex);
    }

    private static void sleep(long delayMs) {
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PangeaAuditException("CONNECTION_ERROR", e);
        }
    }

    private static String resultLocation(JsonNode responseBody) {
        JsonNode location = responseBody == null ? null : responseBody.path("result").path("location");
        if (location != null && location.isTextual() && StringUtils.hasText(location.asText())) {
            return location.asText();
        }
        throw new PangeaAuditException("INVALID_RESPONSE");
    }

    private URI validateLocation(String location) {
        try {
            URI configured = new URI(properties.getUrl());
            URI result = new URI(location);
            if (!"https".equalsIgnoreCase(result.getScheme()) || result.getHost() == null
                    || result.getUserInfo() != null || !result.getHost().equalsIgnoreCase(configured.getHost())
                    || effectivePort(result) != effectivePort(configured)) {
                throw new PangeaAuditException("BAD_LOCATION");
            }
            return result;
        } catch (URISyntaxException e) {
            throw new PangeaAuditException("BAD_LOCATION", e);
        }
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() < 0 ? 443 : uri.getPort();
    }

    private Map<String, Object> requestBody(AuditMessage message) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("action_type", message.actionType());
        event.put("originator", ORIGINATOR);
        event.put("tenant_id", message.zoneId());
        event.put("actor_uuid", message.actorUuid());
        event.put("resource", "zone-background-image");
        event.put("resource_uuid", message.zoneId());
        event.put("batch_id", message.batchId());
        event.put("actor_name", message.actorName());
        event.put("actor_display_name", message.actorDisplayName());
        event.put("description", message.description());
        event.put("app_name", properties.getAppName());
        event.put("event_time", EVENT_TIME_FORMAT.format(message.eventTime()));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("config_id", properties.getConfigId());
        body.put("verbose", false);
        body.put("event", event);
        return body;
    }

    private static HttpHeaders headers(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(Objects.requireNonNull(token));
        return headers;
    }

    private void logSuccess(AuditMessage message, int attempt) {
        logger.info("Pangea audit sent action_type={} op={} attempt={}",
                message.actionType(), message.batchId(), attempt);
    }

    private static boolean isTimeout(ResourceAccessException exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof SocketTimeoutException || cause instanceof HttpTimeoutException) {
                return true;
            }
        }
        return false;
    }

    private static RestTemplate createRestTemplate(PangeaAuditProperties properties) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                // Never follow redirects: the bearer token must not be forwarded to another host.
                connection.setInstanceFollowRedirects(false);
            }
        };
        factory.setConnectTimeout(properties.getConnectTimeoutMs());
        factory.setReadTimeout(properties.getReadTimeoutMs());
        return new RestTemplate(factory);
    }

    private record PostResult(ResponseEntity<JsonNode> response, int attempt) {
    }

    private static final class TokenHolder {
        private final PangeaAuditProperties properties;
        private final RestTemplate restTemplate;
        private final Clock clock;
        private final boolean useVault;
        private String cachedToken;
        private Instant fetchedAt;

        private TokenHolder(PangeaAuditProperties properties, RestTemplate restTemplate, Clock clock) {
            this.properties = properties;
            this.restTemplate = restTemplate;
            this.clock = clock;
            useVault = StringUtils.hasText(properties.getVaultUri())
                    && StringUtils.hasText(properties.getVaultToken())
                    && StringUtils.hasText(properties.getVaultTokenId());
        }

        private boolean isVault() {
            return useVault;
        }

        private synchronized String get() {
            if (!useVault) {
                return properties.getToken();
            }
            Instant now = clock.instant();
            if (cachedToken != null && fetchedAt != null
                    && !now.isAfter(fetchedAt.plus(Duration.ofMinutes(properties.getVaultTokenRefreshMinutes())))) {
                return cachedToken;
            }
            cachedToken = fetchVaultToken();
            fetchedAt = clock.instant();
            return cachedToken;
        }

        private synchronized void invalidate() {
            cachedToken = null;
            fetchedAt = null;
        }

        private String fetchVaultToken() {
            HttpEntity<Map<String, String>> request = new HttpEntity<>(Map.of("id", properties.getVaultTokenId()),
                    headers(properties.getVaultToken()));
            for (int attempt = 0; attempt < properties.getRetryCounter(); attempt++) {
                try {
                    ResponseEntity<JsonNode> response = restTemplate.postForEntity(
                            URI.create(properties.getVaultUri()), request, JsonNode.class);
                    String token = vaultToken(response.getBody());
                    if (response.getStatusCode().value() == 200 && StringUtils.hasText(token)) {
                        return token;
                    }
                    throw new PangeaAuditException("INVALID_RESPONSE");
                } catch (HttpStatusCodeException e) {
                    int status = e.getStatusCode().value();
                    if (status < 500 || attempt + 1 >= properties.getRetryCounter()) {
                        throw new PangeaAuditException("HTTP_" + status, e);
                    }
                    sleep(properties.getRetryIntervalMs());
                } catch (ResourceAccessException e) {
                    throw new PangeaAuditException(isTimeout(e) ? "TIMEOUT" : "CONNECTION_ERROR", e);
                } catch (PangeaAuditException e) {
                    throw e;
                } catch (Exception e) {
                    throw new PangeaAuditException("INVALID_RESPONSE", e);
                }
            }
            throw new PangeaAuditException("INVALID_RESPONSE");
        }

        private static String vaultToken(JsonNode body) {
            JsonNode token = body == null ? null : body.path("result").path("item_versions").path(0).path("token");
            return token != null && token.isTextual() ? token.asText() : null;
        }
    }

    public record AuditMessage(String actionType, String zoneId, String batchId, String description,
                               String actorUuid, String actorName, String actorDisplayName, Instant eventTime) {
    }
}