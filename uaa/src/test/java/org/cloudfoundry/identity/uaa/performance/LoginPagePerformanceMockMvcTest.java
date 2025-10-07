package org.cloudfoundry.identity.uaa.performance;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StopWatch;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.net.URI;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.csrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZoneAndReturnResult;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLoginForm;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class LoginPagePerformanceMockMvcTest {

    private AlphanumericRandomValueStringGenerator generator;

    @MockitoBean
    OidcMetadataFetcher oidcMetadataFetcher;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private FilterRegistrationBean<LimitedModeUaaFilter> limitedModeUaaFilter;

    @Autowired
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;

    @Autowired
    private IdentityZoneConfigurationBootstrap identityZoneConfigurationBootstrap;

    @Autowired
    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    @BeforeEach
    void setUpContext(
    ) {
        generator = new AlphanumericRandomValueStringGenerator();
        SecurityContextHolder.clearContext();

        assertThat(limitedModeUaaFilter.getFilter().isEnabled()).isFalse();
    }

    @AfterEach
    void resetGenerator(
    ) {
        jdbcExpiringCodeStore.setGenerator(new RandomValueStringGenerator(24));
    }

    @AfterEach
    void tearDown() throws Exception {
        MockMvcUtils.setSelfServiceCreateAccountEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), true);
        MockMvcUtils.setSelfServiceResetPasswordEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), true);
        identityZoneConfigurationBootstrap.afterPropertiesSet();
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    void idpDiscoveryRedirectsToOIDCProvider() throws Exception {
        String subdomain = "oidc-discovery-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().setIdpDiscoveryEnabled(true);
        UaaClientDetails client = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        client.setClientSecret("admin-secret");
        createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, client, zone, false, IdentityZoneHolder.getCurrentZoneId());


        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", null);
        String originKey = createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code", "test.org");

        MockHttpSession session = new MockHttpSession();
        getLoginForm(mockMvc, session);

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        for (int i = 0; i < 1000; i++) {
            MvcResult mvcResult = mockMvc.perform(get("/login")
                            .with(csrf(session))
                            .header("Accept", TEXT_HTML)
                            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                    .andExpect(status().isOk())
                    .andReturn();
            MockHttpServletResponse response = mvcResult.getResponse();
        }

        stopWatch.stop();
        long totalTimeMillis = stopWatch.getTotalTimeMillis();

        System.out.println(totalTimeMillis + "ms");
    }

    private static String createOIDCProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, AlphanumericRandomValueStringGenerator generator, IdentityZone zone, String responseType, String domain) throws Exception {
        String originKey = generator.generate();
        AbstractExternalOAuthIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("http://myauthurl.com").toURL());
        definition.setTokenKey("key");
        definition.setTokenUrl(URI.create("http://mytokenurl.com").toURL());
        definition.setRelyingPartyId("id");
        definition.setRelyingPartySecret("secret");
        definition.setLinkText("my oidc provider");
        if (StringUtils.hasText(responseType)) {
            definition.setResponseType(responseType);
        }
        if (StringUtils.hasText(domain)) {
            definition.setEmailDomain(Collections.singletonList(domain));
        }

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(OriginKeys.OIDC10);
        identityProvider.setConfig(definition);
        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);
        return originKey;
    }

    private static IdentityProvider createIdentityProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, IdentityZone identityZone, IdentityProvider activeIdentityProvider) {
        activeIdentityProvider.setIdentityZoneId(identityZone.getId());
        return jdbcIdentityProviderProvisioning.create(activeIdentityProvider, identityZone.getId());
    }
}
