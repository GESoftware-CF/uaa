package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.authentication.UTF8ConversionFilter;
import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Arrays;

@Configuration
@ComponentScan("org.cloudfoundry.identity.uaa")
public class SpringServletXml {

    @Autowired
    CorsProperties corsProperties;

    @Autowired
    IdentityZoneManager identityZoneManager;

    @Bean
    BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameter() {
        return new BackwardsCompatibleScopeParsingFilter();
    }
    @Bean
    YamlConfigurationValidator uaaConfigValidation(@Value("${environmentYamlKey}") String environmentYamlKey) {
        YamlConfigurationValidator bean = new YamlConfigurationValidator(new UaaConfiguration.UaaConfigConstructor());
        bean.setYaml(environmentYamlKey);
        return bean;
    }

    @Bean
    @Primary
    ContentNegotiationManagerFactoryBean contentNegotiationManager() {
        ContentNegotiationManagerFactoryBean bean = new ContentNegotiationManagerFactoryBean();
        bean.setFavorPathExtension(false);
        bean.setFavorParameter(true);
        bean.addMediaType("json", MediaType.APPLICATION_JSON);
        bean.addMediaType("xml", MediaType.APPLICATION_XML);
        bean.addMediaType("html", MediaType.TEXT_HTML);
        return bean;
    }

    @Bean
    RequestMappingHandlerMapping requestMappingHandlerMapping(
            @Qualifier("contentNegotiationManager") ContentNegotiationManagerFactoryBean contentNegotiationManagerFactoryBean
    ) {
        RequestMappingHandlerMapping bean = new RequestMappingHandlerMapping();
        bean.setContentNegotiationManager(contentNegotiationManagerFactoryBean.build());
        bean.setUseSuffixPatternMatch(false);
        bean.setOrder(1);
        return bean;
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

}
