package org.cloudfoundry.identity.uaa.media.config;

import jakarta.servlet.Filter;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {BackgroundImageSecurityConfiguration.class,
        BackgroundImageSecurityConfigurationTest.TestConfiguration.class})
@WebAppConfiguration
class BackgroundImageSecurityConfigurationTest {
    private static final String ZONE_ID = "subzone-id";
    private static final String TOKEN = "background-image-test-token";

    @Autowired private WebApplicationContext context;
    @Autowired private UaaTokenServices tokenServices;
    @Autowired private ProbeEndpoint endpoint;
    @Autowired @Qualifier("springSecurityFilterChain") private Filter securityFilter;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        reset(tokenServices);
        clearInvocations(endpoint);
        SecurityContextHolder.clearContext();
        IdentityZone zone = new IdentityZone();
        zone.setId(ZONE_ID);
        zone.setSubdomain("subzone");
        IdentityZoneHolder.set(zone);
        mockMvc = MockMvcBuilders.webAppContextSetup(context).addFilters(securityFilter).build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "DELETE"})
    void shouldDenyWriteWhenUnauthenticated(String method) throws Exception {
        mockMvc.perform(request(HttpMethod.valueOf(method), writePath(method)))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(tokenServices, endpoint);
    }

    @ParameterizedTest
    @CsvSource({"POST,openid", "DELETE,openid",
            "POST,zones.other-zone.admin", "DELETE,zones.other-zone.admin"})
    void shouldDenyWriteWhenScopeDoesNotAuthorizeCurrentZone(String method, String scope) throws Exception {
        when(tokenServices.loadAuthentication(TOKEN)).thenReturn(authentication(scope));

        mockMvc.perform(request(HttpMethod.valueOf(method), writePath(method))
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isForbidden());

        verifyNoInteractions(endpoint);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa.admin", "zones.write", "zones.subzone-id.admin"})
    void shouldAllowUploadAndDeleteWhenScopeAuthorizesSubzone(String scope) throws Exception {
        when(tokenServices.loadAuthentication(TOKEN)).thenReturn(authentication(scope));

        mockMvc.perform(request(HttpMethod.POST, "/background_images/upload")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isNoContent());
        mockMvc.perform(request(HttpMethod.DELETE, "/background_images")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isNoContent());

        verify(tokenServices, times(2)).loadAuthentication(TOKEN);
        verify(endpoint, times(2)).handle();
    }

    @ParameterizedTest
    @CsvSource({"GET,/background_images", "GET,/background_images/upload",
            "PUT,/background_images/upload", "PATCH,/background_images",
            "HEAD,/background_images", "OPTIONS,/background_images", "POST,/background_images"})
    void shouldDenyUnsupportedRequestEvenWhenUaaAdmin(String method, String path) throws Exception {
        when(tokenServices.loadAuthentication(TOKEN)).thenReturn(authentication("uaa.admin"));

        mockMvc.perform(request(HttpMethod.valueOf(method), path)
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isForbidden());

        verifyNoInteractions(endpoint);
    }

    private static String writePath(String method) {
        return "POST".equals(method) ? "/background_images/upload" : "/background_images";
    }

    private static OAuth2Authentication authentication(String scope) {
        OAuth2Request request = new OAuth2Request(Map.of(), "test-client", AuthorityUtils.NO_AUTHORITIES,
                true, Set.of(scope), Set.of(), null, Set.of(), Map.of());
        return new OAuth2Authentication(request, null);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    static class TestConfiguration {
        @Bean
        UaaTokenServices tokenServices() {
            return mock(UaaTokenServices.class);
        }

        @Bean
        OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
            return new OAuth2AccessDeniedHandler();
        }

        @Bean
        OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
            return new OAuth2AuthenticationEntryPoint();
        }

        @Bean
        ProbeEndpoint probeEndpoint() {
            return spy(new ProbeEndpoint());
        }
    }

    @RestController
    @RequestMapping("/background_images")
    static class ProbeEndpoint {
        @RequestMapping({"", "/**"})
        ResponseEntity<Void> handle() {
            return ResponseEntity.noContent().build();
        }
    }
}