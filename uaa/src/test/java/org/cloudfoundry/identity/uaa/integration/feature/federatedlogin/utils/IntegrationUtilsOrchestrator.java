package org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.utils;


import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.Assert;
import org.junit.Rule;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.CSRF_PARAMETER_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.util.StringUtils.hasText;
public class IntegrationUtilsOrchestrator {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private static final Pattern CSRF_FORM_ELEMENT = Pattern.compile(
            "\\<input type=\\\"hidden\\\" name=\\\"" + CSRF_PARAMETER_NAME + "\\\" value=\\\"(.*?)\\\""
    );

    private static final DefaultResponseErrorHandler fiveHundredErrorHandler = new DefaultResponseErrorHandler() {
        @Override
        protected boolean hasError(HttpStatus statusCode) {
            return statusCode.is5xxServerError();
        }
    };


    public static ClientCredentialsResourceDetails getClientCredentialsResource(String url,
                                                                                String[] scope,
                                                                                String clientId,
                                                                                String clientSecret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        if (scope != null) {
            resource.setScope(Arrays.asList(scope));
        }
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(url + "/oauth/token");
        return resource;
    }

    public static RestTemplate getClientCredentialsTemplate(ClientCredentialsResourceDetails details) {
        RestTemplate client = new OAuth2RestTemplate(details);
        client.setRequestFactory(new StatelessRequestFactory());
        client.setErrorHandler(new OAuth2ErrorHandler(details) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        return client;
    }

    public static ScimUser createUser(RestTemplate client,
                                      String url,
                                      String username,
                                      String firstName,
                                      String lastName,
                                      String email,
                                      boolean verified) {
        return createUserWithPhone(client, url, username, firstName, lastName, email, verified, null);
    }

    public static ScimUser createUserWithPhone(RestTemplate client,
                                               String url,
                                               String username,
                                               String firstName,
                                               String lastName,
                                               String email,
                                               boolean verified,
                                               String phoneNumber) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("secr3T");
        user.setPhoneNumbers(Collections.singletonList(new PhoneNumber(phoneNumber)));
        return client.postForEntity(url + "/Users", user, ScimUser.class).getBody();
    }

    public static ScimGroup createGroup(String token,
                                        String zoneId,
                                        String url,
                                        ScimGroup group) {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(fiveHundredErrorHandler);
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroup> createGroup = template.exchange(
                url + "/Groups",
                HttpMethod.POST,
                new HttpEntity<>(JsonUtils.writeValueAsBytes(group), headers),
                ScimGroup.class
        );
        return createGroup.getBody();
    }


    private static IdentityZone createOrchZone(RestTemplate client,
                                               String url,
                                               String id,
                                               String subdomain,
                                               IdentityZoneConfiguration config,
                                               boolean active) throws Throwable {
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(id);
        orchestratorZoneRequest.setParameters(new OrchestratorZone("adminsecret", subdomain));
        //Create orch zone
        ResponseEntity<OrchestratorZoneResponse> zone = client.postForEntity(url + "/orchestrator/zones", orchestratorZoneRequest, OrchestratorZoneResponse.class);
        //Get orch zone
        ResponseEntity<OrchestratorZoneResponse> zone1 = client.getForEntity(url + "/orchestrator/zones?name=" + id, OrchestratorZoneResponse.class, id);
        //Retrieve Zone ID for Identity Zone from orch Header
        OrchestratorZoneResponse getZoneResponse = zone1.getBody();
        final String zoneId = getZoneResponse.getConnectionDetails().getZone().getHttpHeaderValue();
        //Retrieve
        ResponseEntity<IdentityZone> zoneGet = client.getForEntity(url + "/identity-zones/" + zoneId, IdentityZone.class, id);
        return zoneGet.getBody();
    }


    public static IdentityZone createOrchZone(RestTemplate client,
                                              String url,
                                              String id,
                                              String subdomain,
                                              IdentityZoneConfiguration config) throws Throwable {
        return createOrchZone(client, url, id, subdomain, config, true);
    }

    public static void addMemberToGroup(RestTemplate client,
                                        String url,
                                        String userId,
                                        String groupId
    ) {
        ScimGroupMember groupMember = new ScimGroupMember(userId);
        ResponseEntity<String> response = client.postForEntity(url + "/Groups/{groupId}/members", groupMember, String.class, groupId);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    public static BaseClientDetails getClient(String token,
                                              String url,
                                              String clientId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);

        HttpEntity getHeaders = new HttpEntity<>(null, headers);

        ResponseEntity<BaseClientDetails> response = template.exchange(
                url + "/oauth/clients/" + clientId,
                HttpMethod.GET,
                getHeaders,
                BaseClientDetails.class
        );

        return response.getBody();
    }

    private static List<IdentityProvider> getProviders(String zoneAdminToken,
                                                       String url,
                                                       String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> providerGet = client.exchange(
                url + "/identity-providers",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<IdentityProvider>>() {
            });
        }
        return null;
    }


    public static IdentityProvider createOrUpdateProvider(String accessToken,
                                                          String url,
                                                          IdentityProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<IdentityProvider> existing = getProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (IdentityProvider p : existing) {
                if (p.getOriginKey().equals(provider.getOriginKey()) && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity putHeaders = new HttpEntity<>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(
                            url + "/identity-providers/{id}",
                            HttpMethod.PUT,
                            putHeaders,
                            String.class,
                            provider.getId()
                    );
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), IdentityProvider.class);
                    }
                }
            }
        }

        HttpEntity postHeaders = new HttpEntity<>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(
                url + "/identity-providers",
                HttpMethod.POST,
                postHeaders,
                String.class
        );
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), IdentityProvider.class);
        }
        throw new IllegalStateException("Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }

    public static String getClientCredentialsToken(String baseUrl,
                                                   String clientId,
                                                   String clientSecret) {
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(new StatelessRequestFactory());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = template.exchange(
                baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(formData, headers),
                Map.class);

        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken.getValue();
    }


    public static String getClientCredentialsToken(ServerRunning serverRunning,
                                                   String clientId,
                                                   String clientSecret) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
                "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken.getValue();
    }



    public static class HttpRequestFactory extends HttpComponentsClientHttpRequestFactory {
        private final boolean disableRedirect;
        private final boolean disableCookieHandling;

        HttpRequestFactory(boolean disableCookieHandling, boolean disableRedirect) {
            this.disableCookieHandling = disableCookieHandling;
            this.disableRedirect = disableRedirect;
        }

        @Override
        public HttpClient getHttpClient() {
            HttpClientBuilder builder = HttpClientBuilder.create()
                    .useSystemProperties();
            if (disableRedirect) {
                builder = builder.disableRedirectHandling();
            }
            if (disableCookieHandling) {
                builder = builder.disableCookieManagement();
            }
            return builder.build();
        }
    }


    public static class StatelessRequestFactory extends HttpRequestFactory {
        public StatelessRequestFactory() {
            super(true, true);
        }
    }

}
