package org.cloudfoundry.identity.uaa.codestore;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

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
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
class CodeStoreSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.CODESTORE)
    UaaFilterChain codestore(
            HttpSecurity http,
            @Qualifier("resourceAgnosticAuthenticationFilter") OAuth2AuthenticationProcessingFilter oauth2ResourceFilter
    ) throws Exception {
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());
        var originalFilterChain = http
                .securityMatcher("/Codes/**")
                .authorizeHttpRequests(authorize -> {
                    authorize.anyRequest().access(
                            anyOf()
                                    .isUaaAdmin()
                                    .hasScope("oauth.login")
                    );
                })
                .authenticationManager(emptyAuthenticationManager)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .addFilterBefore(oauth2ResourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling(exception -> {
                    var authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
                    authenticationEntryPoint.setRealmName("UAA/oauth");
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                    exception.accessDeniedHandler(new OAuth2AccessDeniedHandler());
                })
                .build();
        return new UaaFilterChain(originalFilterChain, "codestore");
    }

}
