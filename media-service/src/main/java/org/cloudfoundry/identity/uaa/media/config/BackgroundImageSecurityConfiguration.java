package org.cloudfoundry.identity.uaa.media.config;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

/**
 * Spring Security filter chain for the {@code /background_images} resource endpoints.
 *
 * <p>Security policy: POST and DELETE require an OAuth2 bearer token with
 * {@code zones.{zoneId}.admin}, {@code zones.write}, or {@code uaa.admin} scope.
 *
 * <p>Note: {@code isZoneAdmin()} only works for the UAA zone because it checks the token's
 * {@code zid} claim against the hardcoded UAA zone. For subzones, a custom authorization
 * manager directly checks the scope {@code zones.{currentZoneId}.admin} without the {@code zid}
 * restriction, so both UAA-zone and subzone admin tokens are accepted.
 */
@Configuration
@EnableWebSecurity
public class BackgroundImageSecurityConfiguration {

    /**
     * Returns an {@link AuthorizationManager} that grants access if the bearer token contains
     * the scope {@code zones.{currentZoneId}.admin}, where {@code currentZoneId} is resolved
     * from {@link IdentityZoneHolder} at request time.
     *
     * <p>This is needed because the built-in {@code isZoneAdmin()} only works for tokens issued
     * by the UAA zone ({@code zid=uaa}). Subzone admin tokens have a different {@code zid} value
     * and are rejected by {@code hasScopeInAuthZone}. This manager checks the scope directly
     * without the {@code zid} restriction, enabling subzone admins to use the endpoint.
     */
    private static AuthorizationManager<RequestAuthorizationContext> isCurrentZoneAdmin() {
        return (authentication, context) -> {
            // Resolved per-request — zone context is thread-local and changes per request
            String zoneId = IdentityZoneHolder.get().getId();
            String requiredScope = "zones." + zoneId + ".admin";
            boolean granted = OAuth2ExpressionUtils.hasAnyScope(authentication.get(), new String[]{requiredScope});
            return new AuthorizationDecision(granted);
        };
    }

    /**
     * Convenience: anyOf().isUaaAdmin() | zones.write | zones.{currentZoneId}.admin
     * Works for both UAA-zone and subzone admin tokens.
     */
    private static AuthorizationManager<RequestAuthorizationContext> writeAccess() {
        return anyOf()
                .isUaaAdmin()
                .hasScope("zones.write")
                .or(isCurrentZoneAdmin())
                .throwOnMissingScope();
    }


    /**
     * Secured filter chain for write operations on {@code /background_images/**}.
     *
     * <p>Handles POST and DELETE — both require a valid OAuth2 bearer token
     * with {@code zones.write}, {@code uaa.admin}, or zone-admin scope.
     *
     * @param http                          Spring Security HTTP builder
     * @param tokenServices                 UAA token services for bearer-token validation
     * @param oauthAccessDeniedHandler      OAuth2 access-denied handler
     * @param oauthAuthenticationEntryPoint OAuth2 authentication entry point
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

        // Placeholder: all auth is handled by oauth2ResourceFilter; explicit ProviderManager prevents Spring Boot auto-configuration
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationProvider() {
            @Override public Authentication authenticate(Authentication auth) { return null; }
            @Override public boolean supports(Class<?> type) { return false; }
        });

        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);

        OAuth2AuthenticationProcessingFilter oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(authenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var access = writeAccess();
        var chain = http
                .securityMatcher("/background_images", "/background_images/**")
                .authenticationManager(emptyAuthenticationManager)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,   "/background_images/upload").access(access)
                        .requestMatchers(HttpMethod.DELETE, "/background_images", "/background_images/**").access(access)
                        .anyRequest().denyAll()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauth2ResourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
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
