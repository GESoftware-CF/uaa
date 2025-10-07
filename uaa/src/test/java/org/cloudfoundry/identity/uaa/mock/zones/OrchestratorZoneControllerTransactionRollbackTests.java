package org.cloudfoundry.identity.uaa.mock.zones;

import net.bytebuddy.utility.RandomString;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientRegistrationService;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
public class OrchestratorZoneControllerTransactionRollbackTests {

    private static final String ZONE_NAME = "The Twiglet Zone";
    private static final String SUB_DOMAIN_NAME = "sub-domain-01";
    private static final String ADMIN_CLIENT_SECRET = "admin-secret-01";

    private MockMvc mockMvc;
    private ApplicationContext applicationContext;

    private String orchestratorZonesReadToken = null;
    private String orchestratorZonesWriteToken = null;

    @BeforeEach
    void setUp(@Autowired MockMvc mockMvc, @Autowired ApplicationContext applicationContext,
               @Autowired ClientRegistrationService clientRegistrationService, @Autowired TestClient testClient) throws Exception {
        this.mockMvc = mockMvc;
        this.applicationContext = applicationContext;

        orchestratorZonesReadToken = getAccessToken(
                clientRegistrationService,
                testClient,
                "orchestrator-zone-reader-" + RandomString.make(5).toLowerCase(),
                "r3ader",
                "orchestrator.zones.read");
        orchestratorZonesWriteToken = getAccessToken(
                clientRegistrationService,
                testClient,
                "orchestrator-zone-provisioner-" + RandomString.make(5).toLowerCase(),
                "pr0visioner",
                "orchestrator.zones.read,orchestrator.zones.write");
    }

    private String getAccessToken(ClientRegistrationService clientRegistrationService,
                                  TestClient testClient,
                                  String clientId,
                                  String clientSecret,
                                  String scope) throws Exception {
        UaaClientDetails clientDetails = new UaaClientDetails(
                clientId,
                null,
                "uaa.none",
                "client_credentials",
                scope);
        clientDetails.setClientSecret(clientSecret);
        clientRegistrationService.addClientDetails(clientDetails);
        return testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, scope);
    }

    @Test
    void testCreateZone_TransactionRollBack() throws Exception {

        BeanDefinitionRegistry registry = null;
        BeanDefinition originalBeanDefinition = null;
        try {
            AutowireCapableBeanFactory factory = applicationContext.getAutowireCapableBeanFactory();
            registry = (BeanDefinitionRegistry) factory;
            originalBeanDefinition = registry.getBeanDefinition("identityProviderProvisioning");

            GenericBeanDefinition genericBeanDefinition = new GenericBeanDefinition();
            genericBeanDefinition.setBeanClass(MockIdentityProviderProvisioning.class);
            registry.removeBeanDefinition("identityProviderProvisioning");

            registry.registerBeanDefinition("identityProviderProvisioning", genericBeanDefinition);

            OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                                         SUB_DOMAIN_NAME);

            MvcResult result = mockMvc.perform(post("/orchestrator/zones")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken)
                    .contentType(APPLICATION_JSON).content(
                    JsonUtils.writeValueAsString(orchestratorZoneRequest))).andReturn();

            processZoneAPI(get("/orchestrator/zones"), ZONE_NAME, status().isNotFound());
        } finally {
            assertNotNull(originalBeanDefinition);
            registry.removeBeanDefinition("identityProviderProvisioning");
            registry.registerBeanDefinition("identityProviderProvisioning", originalBeanDefinition);
        }
    }

    private OrchestratorZoneResponse processZoneAPI(MockHttpServletRequestBuilder mockRequestBuilder,
                                                    String nameParameter, ResultMatcher expectedStatus)
        throws Exception {
        MvcResult result =
            mockMvc.perform(mockRequestBuilder.param("name", nameParameter).
                    header("Authorization", "Bearer " + orchestratorZonesReadToken))
                    .andExpect(expectedStatus).andReturn();
        if (StringUtils.hasLength(result.getResponse().getContentAsString()) &&
            result.getResponse().getStatus() == 200) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), OrchestratorZoneResponse.class);
        } else {
            return null;
        }
    }

    private OrchestratorZoneRequest getOrchestratorZoneRequest(String name, String adminClientSecret,
                                                               String subdomain) {
        OrchestratorZone orchestratorZone = new OrchestratorZone(adminClientSecret, subdomain, null);
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(name);
        orchestratorZoneRequest.setParameters(orchestratorZone);
        return orchestratorZoneRequest;
    }
}