package org.cloudfoundry.identity.uaa.audit.pangea;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.util.Throwables.getStackTraceAsString;

class PangeaAuditConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(PangeaAuditClient.class, ListenerImport.class);

    @Test
    void isDisabledAndListenerBeanAbsentWhenEnabledPropertyIsUnset() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(PangeaAuditProperties.class);
            assertThat(context).doesNotHaveBean(PangeaAuditClient.class);
            assertThat(context).doesNotHaveBean(BackgroundImagePangeaAuditListener.class);
        });
    }

    @Test
    void bindsExplicitEnvironmentNamesWithoutExposingToken() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/v1/events",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_TOKEN", "secret-token-value",
                "PANGEA_AUDIT_APP_NAME", "uaa-test",
                "PANGEA_AUDIT_RETRY_COUNTER", "7",
                "PANGEA_AUDIT_RETRY_INTERVAL_MS", "250"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PangeaAuditProperties properties = context.getBean(PangeaAuditProperties.class);
                    assertThat(properties.isEnabled()).isTrue();
                    assertThat(properties.getUrl()).isEqualTo("https://audit.example.test/v1/events");
                    assertThat(properties.getConfigId()).isEqualTo("config-1");
                    assertThat(properties.getToken()).isEqualTo("secret-token-value");
                    assertThat(properties.getAppName()).isEqualTo("uaa-test");
                    assertThat(properties.getRetryCounter()).isEqualTo(7);
                    assertThat(properties.getRetryIntervalMs()).isEqualTo(250);
                    assertThat(properties.getConnectTimeoutMs()).isEqualTo(2000);
                    assertThat(properties.getReadTimeoutMs()).isEqualTo(5000);
                    assertThat(properties.toString()).doesNotContain("secret-token-value");
                    assertThat(context).hasSingleBean(PangeaAuditClient.class)
                            .hasSingleBean(BackgroundImagePangeaAuditListener.class)
                            .doesNotHaveBean(RestTemplate.class);
                });
    }

    @Test
    void fallsBackToSharedUmsSecretKeyNames() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/v2/log",
                "PANGEA_AUDIT_VAULT_URI", "https://vault.example.test/v2/get"))
                .withPropertyValues(
                        "audit.pangea.configid=cfg-shared",
                        "audit.pangea.vault.token=vault-token-shared",
                        "audit.pangea.vault.tokenid=vault-token-id-shared")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PangeaAuditProperties properties = context.getBean(PangeaAuditProperties.class);
                    assertThat(properties.getConfigId()).isEqualTo("cfg-shared");
                    assertThat(properties.getVaultToken()).isEqualTo("vault-token-shared");
                    assertThat(properties.getVaultTokenId()).isEqualTo("vault-token-id-shared");
                    assertThat(properties.toString()).doesNotContain("vault-token-shared");
                });
    }

    @Test
    void explicitPangeaAuditValuesTakePrecedenceOverSharedSecretKeys() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/v2/log",
                "PANGEA_AUDIT_CONFIG_ID", "explicit-config"))
                .withPropertyValues("audit.pangea.configid=shared-config", "audit.pangea.token=shared-token")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(PangeaAuditProperties.class).getConfigId())
                            .isEqualTo("explicit-config");
                });
    }

    @Test
    void createsClientWhenVaultCredentialsAreConfigured() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/v1/events",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_VAULT_URI", "https://vault.example.test/v1/item",
                "PANGEA_AUDIT_VAULT_TOKEN", "vault-secret",
                "PANGEA_AUDIT_VAULT_TOKEN_ID", "pangea-token",
                "PANGEA_AUDIT_VAULT_TOKEN_REFRESH_MINUTES", "60"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(PangeaAuditClient.class)).isNotNull();
                    assertThat(context).doesNotHaveBean(RestTemplate.class);
                });
    }

    @Test
    void rejectsNonHttpsVaultUriWithoutPrintingValues() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/events",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_TOKEN", "private-token",
                "PANGEA_AUDIT_VAULT_URI", "http://vault.example.test/item?credential=private",
                "PANGEA_AUDIT_VAULT_TOKEN", "vault-secret",
                "PANGEA_AUDIT_VAULT_TOKEN_ID", "pangea-token"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    String trace = trace(context);
                    assertThat(trace).contains("PANGEA_AUDIT_VAULT_URI")
                            .doesNotContain("private-token", "vault-secret", "credential=private");
                });
    }

    @Test
    void failsClearlyWhenEnabledConfigurationIsIncomplete() {
        withPangeaEnvironment(Map.of("PANGEA_AUDIT_ENABLED", "true"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    String trace = trace(context);
                    assertThat(trace).contains("PANGEA_AUDIT_URL", "PANGEA_AUDIT_CONFIG_ID")
                            .doesNotContain("secret");
                });
    }

    @Test
    void rejectsNonHttpsEndpointWithoutPrintingValues() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "http://audit.example.test/events?credential=private",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_TOKEN", "private-token"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    String trace = trace(context);
                    assertThat(trace).contains("PANGEA_AUDIT_URL")
                            .doesNotContain("private-token", "credential=private");
                });
    }

    @Test
    void requiresStaticTokenOrCompleteVaultTrio() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/events",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_VAULT_URI", "https://vault.example.test/v1/item",
                "PANGEA_AUDIT_VAULT_TOKEN", "vault-secret"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    String trace = trace(context);
                    assertThat(trace).contains("PANGEA_AUDIT_TOKEN", "PANGEA_AUDIT_VAULT_TOKEN_ID")
                            .doesNotContain("vault-secret");
                });
    }

    @Test
    void rejectsVaultRefreshOutsideSupportedRangeWhenEnabled() {
        withPangeaEnvironment(Map.of(
                "PANGEA_AUDIT_ENABLED", "true",
                "PANGEA_AUDIT_URL", "https://audit.example.test/events",
                "PANGEA_AUDIT_CONFIG_ID", "config-1",
                "PANGEA_AUDIT_TOKEN", "static-token",
                "PANGEA_AUDIT_VAULT_TOKEN_REFRESH_MINUTES", "1441"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(trace(context)).contains("PANGEA_AUDIT_VAULT_TOKEN_REFRESH_MINUTES");
                });
    }

    private static String trace(org.springframework.boot.test.context.assertj.AssertableApplicationContext context) {
        return getStackTraceAsString(context.getStartupFailure());
    }

    private ApplicationContextRunner withPangeaEnvironment(Map<String, Object> variables) {
        // The property-source name must end in "-systemEnvironment" for Spring Boot's
        // relaxed binding (PANGEA_AUDIT_URL -> pangea.audit.url) to apply to it.
        return contextRunner.withInitializer(context -> context.getEnvironment().getPropertySources()
                .addFirst(new SystemEnvironmentPropertySource("pangea-test-systemEnvironment", variables)));
    }

    @Configuration(proxyBeanMethods = false)
    @Import(BackgroundImagePangeaAuditListener.class)
    static class ListenerImport {
    }
}