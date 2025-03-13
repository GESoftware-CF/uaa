package org.cloudfoundry.identity.uaa.client;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

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

@Configuration
@EnableWebSecurity
class ClientAdminSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.CLIENT_SECRET_CATCHALL)
    UaaFilterChain clientAdminCatchAll(
            HttpSecurity http,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("clientAdminOAuth2ResourceFilter") OAuth2AuthenticationProcessingFilter resourceFilter
    ) throws Exception {
        var emptyAuthManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());
        var originalChain = http
                .securityMatcher("/oauth/clients/**")
                .authenticationManager(emptyAuthManager)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.GET, "oauth/clients/meta", "/oauth/clients/*/meta").fullyAuthenticated();
                    auth.requestMatchers(HttpMethod.GET, "/oauth/clients/**").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScope("clients.read", "clients.admin")
                    );

                    var canWriteClients = anyOf()
                            .isUaaAdmin()
                            .isZoneAdmin()
                            .hasScope("clients.write", "clients.admin");
                    auth.requestMatchers(HttpMethod.POST, "/oauth/clients/**").access(canWriteClients);
                    auth.requestMatchers(HttpMethod.PUT, "/oauth/clients/**").access(canWriteClients);
                    auth.requestMatchers(HttpMethod.DELETE, "/oauth/clients/**").access(canWriteClients);

                    auth.anyRequest().denyAll();
                })
                .addFilterAt(resourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .build();

        return new UaaFilterChain(originalChain, "clientAdminCatchAll");
    }


    // TODO: object provider?
    @Bean(name = "clientAdminOAuth2ResourceFilter")
    public OAuth2AuthenticationProcessingFilter clientAdminOAuth2ResourceFilter(UaaTokenServices tokenServices, @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint) {
        var oauth2AuthenticationManager = new OAuth2AuthenticationManager();
        oauth2AuthenticationManager.setTokenServices(tokenServices);
        var oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(oauth2AuthenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        return oauth2ResourceFilter;
    }

}
