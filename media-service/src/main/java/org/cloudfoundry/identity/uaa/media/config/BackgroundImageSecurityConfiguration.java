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
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

/**
 * Spring Security filter chain for the {@code /background_images} resource endpoints.
 *
 * <p>Security policy:
 * <ul>
 *   <li>GET  /background_images/**  – fully public, no authentication required, no token parsing</li>
 *   <li>POST, PATCH, DELETE /background_images/** – requires OAuth2 bearer token with
 *       {@code zones.write}, {@code uaa.admin}, or zone-admin scope</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class BackgroundImageSecurityConfiguration {

    /**
     * Fully public filter chain for all {@code GET /background_images/**} requests.
     *
     * <p>This chain runs <em>before</em> the main {@code backgroundImages} chain (order 950)
     * and permits all GET requests without any token parsing, authentication, or CSRF checks.
     * No {@code Authorization} header is required or inspected.
     *
     * @param http Spring Security HTTP builder
     * @return configured {@link UaaFilterChain}
     * @throws Exception if configuration fails
     */
    @Bean
    @Order(FilterChainOrder.BACKGROUND_IMAGES_PUBLIC)
    public UaaFilterChain backgroundImagePublicGet(HttpSecurity http) throws Exception {
        var chain = http
                .securityMatcher(request ->
                        request.getMethod().equalsIgnoreCase(HttpMethod.GET.name())
                        && request.getRequestURI().startsWith("/background_images"))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(chain, "backgroundImagePublicGet");
    }

    /**
     * Secured filter chain for write operations on {@code /background_images/**}.
     *
     * <p>Handles POST, PATCH, and DELETE — all require a valid OAuth2 bearer token
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

        var emptyAuthenticationManager = new ProviderManager(
                new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());

        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);

        OAuth2AuthenticationProcessingFilter oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(authenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var chain = http
                .securityMatcher("/background_images", "/background_images/**")
                .authenticationManager(emptyAuthenticationManager)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,   "/background_images", "/background_images/upload").access(
                                anyOf().isUaaAdmin().isZoneAdmin().hasScope("zones.write").throwOnMissingScope())
                        .requestMatchers(HttpMethod.PATCH,  "/background_images", "/background_images/**").access(
                                anyOf().isUaaAdmin().isZoneAdmin().hasScope("zones.write").throwOnMissingScope())
                        .requestMatchers(HttpMethod.DELETE, "/background_images", "/background_images/**").access(
                                anyOf().isUaaAdmin().isZoneAdmin().hasScope("zones.write").throwOnMissingScope())
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
