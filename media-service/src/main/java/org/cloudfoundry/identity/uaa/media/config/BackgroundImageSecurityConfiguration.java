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
 *   <li>POST /background_images – requires OAuth2 bearer token with {@code zones.write} or
 *       {@code uaa.admin} scope (same as admin API)</li>
 *   <li>GET  /background_images/** – publicly accessible (no authentication required)</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class BackgroundImageSecurityConfiguration {

    /**
     * Security filter chain for background image endpoints.
     *
     * @param http                         Spring Security HTTP builder
     * @param tokenServices                UAA token services for bearer-token validation
     * @param oauthAccessDeniedHandler     OAuth2 access-denied handler
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
                .authorizeHttpRequests(auth -> {
                    // POST /background_images and /background_images/upload – admin only (zones.write or uaa.admin)
                    auth.requestMatchers(HttpMethod.POST, "/background_images", "/background_images/upload").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScope("zones.write")
                                    .throwOnMissingScope()
                    );
                    // GET endpoints – publicly accessible
                    auth.anyRequest().permitAll();
                })
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
