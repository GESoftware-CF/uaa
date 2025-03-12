package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class TokenIntrospectionSecurityConfiguration {
    @Autowired
    @Qualifier("basicAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint basicAuthenticationEntryPoint;

    @Autowired
    @Qualifier("clientAuthenticationManager")
    AuthenticationManager clientAuthenticationManager;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWithoutResourceAuthenticationFilter")
    OAuth2AuthenticationProcessingFilter oauthWithoutResourceAuthenticationFilter;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    ClientBasicAuthenticationFilter clientAuthenticationFilter;

    @Bean
    @Order(FilterChainOrder.RATE_LIMIT)
    UaaFilterChain checkTokenSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/check_token")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").hasAuthority("uaa.resource");
                    auth.anyRequest().denyAll();
                })
                //TODO is the auth manager needed?
                .authenticationManager(clientAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "checkTokenSecurity");
    }

    @Bean
    @Order(FilterChainOrder.RATE_LIMIT)
    UaaFilterChain introspectSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/introspect")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").hasAuthority("uaa.resource");
                    auth.anyRequest().denyAll();
                })
                //TODO is the auth manager needed?
                .authenticationManager(clientAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauthWithoutResourceAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "introspectSecurity");
    }
}