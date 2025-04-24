package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.authentication.UTF8ConversionFilter;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SpringServletXmlFiltersConfiguration {

    @Autowired
    CorsProperties corsProperties;

    @Autowired
    LimitedModeProperties limitedModeProperties;

    @Autowired
    IdentityZoneManager identityZoneManager;

    @Bean
    BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameter() {
        return new BackwardsCompatibleScopeParsingFilter();
    }
    @Bean
    DisableIdTokenResponseTypeFilter disableIdTokenResponseFilter(
            @Value("${oauth.id_token.disable:false}") boolean disable
    ) {
        DisableIdTokenResponseTypeFilter bean = new DisableIdTokenResponseTypeFilter(
                disable,
                Arrays.asList("/**/oauth/authorize", "/oauth/authorize")
        );
        return bean;
    }

    @Bean
    Class<OAuth2AuthenticationProcessingFilter> oauth2TokenParseFilter() {
        return OAuth2AuthenticationProcessingFilter.class;
    }

    @Bean
    UTF8ConversionFilter utf8ConversionFilter() {
        return new UTF8ConversionFilter();
    }

    @Bean
    CorsFilter corsFilter() {
        CorsFilter bean = new CorsFilter(identityZoneManager, corsProperties.enforceSystemZoneSettings);

        bean.setCorsAllowedUris(corsProperties.defaultAllowed.uris());
        bean.setCorsAllowedOrigins(corsProperties.defaultAllowed.origins());
        bean.setCorsAllowedHeaders(corsProperties.defaultAllowed.headers());
        bean.setCorsAllowedMethods(corsProperties.defaultAllowed.methods());
        bean.setCorsAllowedCredentials(corsProperties.defaultAllowed.credentials());
        bean.setCorsMaxAge(corsProperties.defaultMaxAge);

        bean.setCorsXhrAllowedUris(corsProperties.xhrAllowed.uris());
        bean.setCorsXhrAllowedOrigins(corsProperties.xhrAllowed.origins());
        bean.setCorsXhrAllowedHeaders(corsProperties.xhrAllowed.headers());
        bean.setCorsXhrAllowedMethods(corsProperties.xhrAllowed.methods());
        bean.setCorsXhrAllowedCredentials(corsProperties.xhrAllowed.credentials());
        bean.setCorsXhrMaxAge(corsProperties.xhrMaxAge);
        return bean;
    }

    @Bean
    LimitedModeUaaFilter limitedModeUaaFilter() {
        LimitedModeUaaFilter bean = new LimitedModeUaaFilter();
        bean.setStatusFile(limitedModeProperties.statusFile);
        bean.setPermittedEndpoints(limitedModeProperties.permitted.endpoints());
        bean.setPermittedMethods(limitedModeProperties.permitted.methods());
        return bean;
    }
}
