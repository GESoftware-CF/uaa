package org.cloudfoundry.identity.uaa.media.config;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * Spring Security filter chain for the {@code /background_images} resource endpoints.
 *
 * <p>All requests to {@code /background_images/**} are protected by OAuth2 bearer-token
 * authentication. A valid JWT access token with the {@code zones.{zoneId}.admin} scope
 * (or {@code uaa.admin}) is required for upload (POST). GET (stream/responsive) endpoints
 * require at minimum an authenticated token.
 */
@Configuration
@EnableWebSecurity
public class BackgroundImageSecurityConfiguration {

    /**
     * Security filter chain for background image endpoints.
     *
     * @param http                          Spring Security HTTP builder
     * @param tokenServices                 UAA token services for bearer token validation
     * @param oauthAccessDeniedHandler      handler for 403 responses
     * @param oauthAuthenticationEntryPoint handler for 401 responses
     * @return configured {@link UaaFilterChain}
     * @throws Exception if configuration fails
     */
    @Bean
    @Order(FilterChainOrder.BACKGROUND_IMAGES)
    public UaaFilterChain backgroundImages(
            HttpSecurity http,
            UaaTokenServices tokenServices,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint
    ) throws Exception {

        var authManager = new OAuth2AuthenticationManager();
        authManager.setTokenServices(tokenServices);
        authManager.setResourceId("background_images");

        var tokenFilter = new OAuth2AuthenticationProcessingFilter();
        tokenFilter.setAuthenticationManager(authManager);
        tokenFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var chain = http
                .securityMatcher("/background_images", "/background_images/**")
                .authorizeHttpRequests(auth -> {
                    // GET endpoints are accessible to any authenticated token
                    auth.requestMatchers(HttpMethod.GET, "/background_images/stream").authenticated();
                    auth.requestMatchers(HttpMethod.GET, "/background_images/responsive").authenticated();
                    // POST requires zones.*.admin or uaa.admin scope
                    auth.requestMatchers(HttpMethod.POST, "/background_images").authenticated();
                    auth.anyRequest().denyAll();
                })
                .addFilterBefore(tokenFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "backgroundImages");
    }
}

