package org.cloudfoundry.identity.uaa.account;

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
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
class UserInfoSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.USERINFO)
    UaaFilterChain userinfo(
            HttpSecurity http,
            UaaTokenServices tokenServices,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint
    ) throws Exception {
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());

        var oauth2AuthenticationManager = new OAuth2AuthenticationManager();
        oauth2AuthenticationManager.setTokenServices(tokenServices);
        oauth2AuthenticationManager.setResourceId("openid");
        var oidcResourceAuthenticationFilter = new OAuth2AuthenticationProcessingFilter();
        oidcResourceAuthenticationFilter.setAuthenticationManager(oauth2AuthenticationManager);
        oidcResourceAuthenticationFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var originalChain = http
                .securityMatcher("/userinfo")
                .authenticationManager(emptyAuthenticationManager) // TODO
                .authorizeHttpRequests(auth -> auth.anyRequest().access(anyOf().hasScope("openid")))
                .addFilterBefore(oidcResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable) // TODO
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .build();
        return new UaaFilterChain(originalChain, "userinfo");
    }

}
