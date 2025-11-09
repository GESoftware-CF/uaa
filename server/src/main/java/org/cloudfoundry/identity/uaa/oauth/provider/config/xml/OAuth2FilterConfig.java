package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import com.ge.predix.pki.device.provider.KeyProviderConfiguration;
import com.ge.predix.pki.device.provider.PredixDeviceRegistryPublicKeyProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.JwtTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.PkceEnhancedAuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.Saml2TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.UserTokenGranter;
import org.cloudfoundry.identity.uaa.provider.JdbcKeyProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.saml.Saml2BearerGrantAuthenticationConverter;
import org.cloudfoundry.identity.uaa.provider.token.JwtBearerAssertionAuthenticationFilter;
import org.cloudfoundry.identity.uaa.provider.token.JwtBearerAssertionTokenGranter;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

@Configuration
@Import(KeyProviderConfiguration.class)
public class OAuth2FilterConfig {

    @Bean
    FilterRegistrationBean<BackwardsCompatibleTokenEndpointAuthenticationFilter> tokenEndpointAuthenticationFilter(
            PasswordGrantAuthenticationManager passwordGrantAuthenticationManager,
            UaaAuthorizationRequestManager authorizationRequestManager,
            Saml2BearerGrantAuthenticationConverter samlBearerGrantAuthenticationProvider,
            ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
            AuthenticationEntryPoint basicAuthenticationEntryPoint
    ) {

        BackwardsCompatibleTokenEndpointAuthenticationFilter filter =
                new BackwardsCompatibleTokenEndpointAuthenticationFilter("/oauth/token/alias/{registrationId}",
                        passwordGrantAuthenticationManager, authorizationRequestManager, samlBearerGrantAuthenticationProvider,
                        externalOAuthAuthenticationManager);
        filter.setAuthenticationDetailsSource(authenticationDetailsSource);
        filter.setAuthenticationEntryPoint(basicAuthenticationEntryPoint);
        FilterRegistrationBean<BackwardsCompatibleTokenEndpointAuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    public PkceEnhancedAuthorizationCodeTokenGranter pkceEnhancedAuthorizationCodeTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("authorizationCodeServices") AuthorizationCodeServices authorizationCodeServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            @Qualifier("pkceValidationServices") PkceValidationService pkceValidationServices) {
        PkceEnhancedAuthorizationCodeTokenGranter tokenGranter = new PkceEnhancedAuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
        tokenGranter.setPkceValidationService(pkceValidationServices);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Bean
    public UserTokenGranter userTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning tokenStore) {
        UserTokenGranter tokenGranter = new UserTokenGranter(tokenServices, clientDetailsService, requestFactory, tokenStore);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Bean
    public JwtTokenGranter jwtTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory) {
        JwtTokenGranter tokenGranter = new JwtTokenGranter(tokenServices, clientDetailsService, requestFactory);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Bean
    public Saml2TokenGranter samlTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory,
            SecurityContextAccessor securityContextAccessor) {
        Saml2TokenGranter tokenGranter = new Saml2TokenGranter(tokenServices, clientDetailsService, requestFactory, securityContextAccessor);
        compositeTokenGranter.addTokenGranter(tokenGranter);

        return tokenGranter;
    }

    @Bean
    public PredixDeviceRegistryPublicKeyProvider publicKeyProvider(@Value("${KEY_PROVIDER_SERVICE_URL:#{null}}") String keyProviderServiceUrl,
                                                                   @Value("${KEY_PROVIDER_DEFAULT_INSTANCE:#{null}}") String keyProviderDefaultInstanceId,
                                                                   RestClient keyProviderTemplate, RestTemplate keyProviderWithTokenTemplate) {
        return new PredixDeviceRegistryPublicKeyProvider(keyProviderServiceUrl, keyProviderDefaultInstanceId, keyProviderTemplate, keyProviderWithTokenTemplate);
    }

    @Bean
    public JwtBearerAssertionTokenGranter jwtBearerTokenGranter(@Qualifier("oauth2TokenGranter") CompositeTokenGranter compositeTokenGranter,
                                           @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
                                           @Qualifier("jdbcClientDetailsService") ClientDetailsService clientDetailsService,
                                           @Qualifier("authorizationRequestManager") OAuth2RequestFactory requestFactory) {
        JwtBearerAssertionTokenGranter tokenGranter = new JwtBearerAssertionTokenGranter(tokenServices, clientDetailsService, requestFactory);
        compositeTokenGranter.addTokenGranter(tokenGranter);
        return tokenGranter;
    }

/*    @Bean
    public JwtBearerAssertionTokenGranter jwtBearerTokenGranter(
            UaaTokenServices tokenServices,
            MultitenantJdbcClientDetailsService jdbcClientDetailsService,
            UaaAuthorizationRequestManager authorizationRequestManager
    ) {
        return new JwtBearerAssertionTokenGranter(tokenServices, jdbcClientDetailsService, authorizationRequestManager);
    }*/

    @Bean
    public JwtBearerAssertionAuthenticationFilter jwtBearerAuthenticationFilter(
            ClientDetailsService jdbcClientDetailsService,
            PredixDeviceRegistryPublicKeyProvider publicKeyProvider,
            JdbcKeyProviderProvisioning keyProviderProvisioning,
            OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("oauth2TokenGranter") CompositeTokenGranter oauth2TokenGranter,
            @Value("${device.assertion.proxy-public-key:override-in-uaa-yml}") String proxyPublicKey
    ) {
        JwtBearerAssertionAuthenticationFilter filter = new JwtBearerAssertionAuthenticationFilter();
        filter.setClientDetailsService(jdbcClientDetailsService);
        filter.setPublicKeyProvider(publicKeyProvider);
        filter.setKeyProviderProvisioning(keyProviderProvisioning);
        filter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        filter.setDcsEndpointTokenGranter(oauth2TokenGranter);
        filter.setProxyPublicKey(proxyPublicKey);
        return filter;
    }
}
