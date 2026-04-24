package org.cloudfoundry.identity.uaa.media.config;

import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * Spring Security filter chain for the {@code /background_images} resource endpoints.
 *
 * <p>TODO: POC mode - all requests are permitted without authentication.
 * Re-enable OAuth2 bearer-token validation before going to production.
 */
@Configuration
@EnableWebSecurity
public class BackgroundImageSecurityConfiguration {

    /**
     * Security filter chain for background image endpoints.
     *
     * @param http Spring Security HTTP builder
     * @return configured {@link UaaFilterChain}
     * @throws Exception if configuration fails
     */
    @Bean
    @Order(FilterChainOrder.BACKGROUND_IMAGES)
    public UaaFilterChain backgroundImages(HttpSecurity http) throws Exception {
        var chain = http
                .securityMatcher("/background_images", "/background_images/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "backgroundImages");
    }
}
