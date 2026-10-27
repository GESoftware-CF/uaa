package org.cloudfoundry.identity.uaa.audit.pangea;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "pangea.audit")
public class PangeaAuditProperties implements EnvironmentAware {
    private Environment environment;
    private boolean enabled;
    private String url = "";
    private String configId = "";
    private String token = "";
    private String appName = "uaa";
    private int retryCounter = 5;
    private long retryIntervalMs = 500;
    private int connectTimeoutMs = 2000;
    private int readTimeoutMs = 5000;
    private String vaultUri = "";
    private String vaultToken = "";
    private String vaultTokenId = "";
    private int vaultTokenRefreshMinutes = 720;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    void validate() {
        if (!enabled) {
            return;
        }
        applySharedSecretFallbacks();
        List<String> errors = new ArrayList<>();
        validateHttpsUrl(url, "PANGEA_AUDIT_URL", errors);
        if (!StringUtils.hasText(configId)) {
            errors.add("PANGEA_AUDIT_CONFIG_ID must be configured");
        }
        boolean hasStaticToken = StringUtils.hasText(token);
        boolean hasAnyVaultConfiguration = StringUtils.hasText(vaultUri)
                || StringUtils.hasText(vaultToken) || StringUtils.hasText(vaultTokenId);
        boolean hasVaultConfiguration = StringUtils.hasText(vaultUri)
                && StringUtils.hasText(vaultToken) && StringUtils.hasText(vaultTokenId);
        if (hasAnyVaultConfiguration && !hasVaultConfiguration) {
            errors.add("PANGEA_AUDIT_VAULT_URI, PANGEA_AUDIT_VAULT_TOKEN, and "
                    + "PANGEA_AUDIT_VAULT_TOKEN_ID must be configured together");
        }
        if (StringUtils.hasText(vaultUri)) {
            validateHttpsUrl(vaultUri, "PANGEA_AUDIT_VAULT_URI", errors);
        }
        if (!hasStaticToken && !hasVaultConfiguration) {
            errors.add("Configure PANGEA_AUDIT_TOKEN or all of PANGEA_AUDIT_VAULT_URI, "
                    + "PANGEA_AUDIT_VAULT_TOKEN, and PANGEA_AUDIT_VAULT_TOKEN_ID");
        }
        if (vaultTokenRefreshMinutes < 1 || vaultTokenRefreshMinutes > 1440) {
            errors.add("PANGEA_AUDIT_VAULT_TOKEN_REFRESH_MINUTES must be between 1 and 1440");
        }
        if (retryCounter < 1) {
            errors.add("PANGEA_AUDIT_RETRY_COUNTER must be positive");
        }
        if (retryIntervalMs < 1) {
            errors.add("PANGEA_AUDIT_RETRY_INTERVAL_MS must be positive");
        }
        if (connectTimeoutMs < 1) {
            errors.add("PANGEA_AUDIT_CONNECT_TIMEOUT_MS must be positive");
        }
        if (readTimeoutMs < 1) {
            errors.add("PANGEA_AUDIT_READ_TIMEOUT_MS must be positive");
        }
        if (!errors.isEmpty()) {
            throw new IllegalStateException(String.join("; ", errors));
        }
    }

    /** Falls back to the dotted key names used by the shared UMS audit secret. */
    private void applySharedSecretFallbacks() {
        if (environment == null) {
            return;
        }
        configId = firstText(configId, environment.getProperty("audit.pangea.configid"));
        token = firstText(token, environment.getProperty("audit.pangea.token"));
        vaultToken = firstText(vaultToken, environment.getProperty("audit.pangea.vault.token"));
        vaultTokenId = firstText(vaultTokenId, environment.getProperty("audit.pangea.vault.tokenid"));
    }

    private static String firstText(String current, String fallback) {
        return StringUtils.hasText(current) ? current : (fallback == null ? "" : fallback);
    }

    private static void validateHttpsUrl(String value, String variable, List<String> errors) {
        if (!StringUtils.hasText(value)) {
            errors.add(variable + " must be configured");
            return;
        }
        try {
            URI endpoint = new URI(value);
            if (!"https".equalsIgnoreCase(endpoint.getScheme()) || !StringUtils.hasText(endpoint.getHost())
                    || endpoint.getUserInfo() != null) {
                errors.add(variable + " must be an HTTPS URL");
            }
        } catch (URISyntaxException e) {
            errors.add(variable + " must be a valid HTTPS URL");
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getConfigId() {
        return configId;
    }

    public void setConfigId(String configId) {
        this.configId = configId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = StringUtils.hasText(appName) ? appName : "uaa";
    }

    public int getRetryCounter() {
        return retryCounter;
    }

    public void setRetryCounter(int retryCounter) {
        this.retryCounter = retryCounter;
    }

    public long getRetryIntervalMs() {
        return retryIntervalMs;
    }

    public void setRetryIntervalMs(long retryIntervalMs) {
        this.retryIntervalMs = retryIntervalMs;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    public String getVaultUri() {
        return vaultUri;
    }

    public void setVaultUri(String vaultUri) {
        this.vaultUri = vaultUri;
    }

    public String getVaultToken() {
        return vaultToken;
    }

    public void setVaultToken(String vaultToken) {
        this.vaultToken = vaultToken;
    }

    public String getVaultTokenId() {
        return vaultTokenId;
    }

    public void setVaultTokenId(String vaultTokenId) {
        this.vaultTokenId = vaultTokenId;
    }

    public int getVaultTokenRefreshMinutes() {
        return vaultTokenRefreshMinutes;
    }

    public void setVaultTokenRefreshMinutes(int vaultTokenRefreshMinutes) {
        this.vaultTokenRefreshMinutes = vaultTokenRefreshMinutes;
    }

    @Override
    public String toString() {
        return "PangeaAuditProperties{enabled=" + enabled + ", appName='" + appName
                + "', retryCounter=" + retryCounter + ", retryIntervalMs=" + retryIntervalMs
                + ", connectTimeoutMs=" + connectTimeoutMs + ", readTimeoutMs=" + readTimeoutMs + '}';
    }
}