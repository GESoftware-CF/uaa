package org.cloudfoundry.identity.uaa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class UaaPropertiesTest {

    @EnableConfigurationProperties({UaaProperties.Servlet.class, UaaProperties.Csp.class, UaaProperties.Metrics.class})
    static class TestUaaServletConfig {}

    private ApplicationContextRunner applicationContextRunner;

    @BeforeEach
    void setup() {
        applicationContextRunner = new ApplicationContextRunner().withUserConfiguration(TestUaaServletConfig.class);
    }

    @Test
    void whenNoServletPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Servlet properties = context.getBean(UaaProperties.Servlet.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.filteredHeaders()).isNotNull();
                    assertThat(properties.filteredHeaders()).containsExactly(
                            "X-Forwarded-For",
                            "X-Forwarded-Host",
                            "X-Forwarded-Proto",
                            "X-Forwarded-Prefix",
                            "Forwarded"
                    );

                });
    }

    @Test
    void whenFilteredHeadersAreSet() {
        applicationContextRunner
                .withPropertyValues("servlet.filtered-headers=X-Forwarded-Host,X-Forwarded-Proto")
                .run(context -> {
                    UaaProperties.Servlet properties = context.getBean(UaaProperties.Servlet.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.filteredHeaders()).isNotNull();
                    assertThat(properties.filteredHeaders()).containsExactly(
                            "X-Forwarded-Host",
                            "X-Forwarded-Proto"
                    );

                });
    }

    @Test
    void whenNoCspPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Csp properties = context.getBean(UaaProperties.Csp.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.scriptSrc()).isNotNull();
                    assertThat(properties.scriptSrc()).containsExactly(
                            "'self'"
                    );

                });
    }

    @Test
    void whenCspPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("csp.script-src='self',custom")
                .run(context -> {
                    UaaProperties.Csp properties = context.getBean(UaaProperties.Csp.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.scriptSrc()).isNotNull();
                    assertThat(properties.scriptSrc()).containsExactly(
                            "'self'", "custom"
                    );

                });
    }

    @Test
    void whenNoMetricsPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    UaaProperties.Metrics properties = context.getBean(UaaProperties.Metrics.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.enabled()).isTrue();
                    assertThat(properties.perRequestMetrics()).isFalse();

                });
    }

    @Test
    void whenMetricsPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("metrics.enabled=false", "metrics.perRequestMetrics=true")
                .run(context -> {
                    UaaProperties.Metrics properties = context.getBean(UaaProperties.Metrics.class);

                    assertThat(properties).isNotNull();
                    assertThat(properties.enabled()).isFalse();
                    assertThat(properties.perRequestMetrics()).isTrue();

                });
    }
}