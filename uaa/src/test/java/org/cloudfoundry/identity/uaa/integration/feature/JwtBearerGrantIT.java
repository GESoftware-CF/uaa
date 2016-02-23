package org.cloudfoundry.identity.uaa.integration.feature;


import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantIT {
    
    private static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String TENANT_ID = "1234";
    private static final String ISSUER_ID = "jwt-machine-client";
    private static final String UNREGISTERED_ISSUER_ID = "jwt-unregistered-client";
    private static final String AUDIENCE =  "http://localhost:8080/uaa/oauth/token";

    @Value("${integration.test.base_url}")
    String baseUrl;
    
    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;
    
    ServerRunning serverRunning = ServerRunning.isRunning();
   
    private OAuth2RestTemplate adminClient;
    
    private RestTemplate machineClient;
    
    @Before
    public void setup() throws Exception {
        System.out.println("baseurl:"+baseUrl);
        //create client with jwt-bearer grant
        this.adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.baseUrl, new String[0], "admin", "adminsecret"));
        BaseClientDetails client = new BaseClientDetails(ISSUER_ID, "none","uaa.none", 
                GRANT_TYPE_JWT_BEARER, "machine.m1.admin", null);
        IntegrationTestUtils.createClient(adminClient.getAccessToken().getValue(), baseUrl, client);
    }
    
    @Test
    public void testJwtBearerGrantNoPublicKey() {
        //create bearer token
        String token = new MockAssertionToken().mockAssertionToken(UNREGISTERED_ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        //call uaa/oauth/token
        this.machineClient = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(new MediaType("application", "x-www-form-urlencoded", StandardCharsets.UTF_8));
        List<MediaType> acceptMediaTypes = new ArrayList<MediaType>();
        acceptMediaTypes.add(new MediaType("application", "json", StandardCharsets.UTF_8));
        headers.setAccept(acceptMediaTypes);
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String,String>();
        formData.add("grant_type", GRANT_TYPE_JWT_BEARER);
        formData.add("assertion", token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        
        ResponseEntity<String> response = this.machineClient.postForEntity(baseUrl + "/oauth/token",
                requestEntity, String.class);
        Assert.assertEquals(HttpStatus.UNAUTHORIZED,response.getStatusCode());
    }
    
//    @Test
    public void testJwtBearerGrantSuccess() {
        //create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        //call uaa/oauth/token
        this.machineClient = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(new MediaType("application", "x-www-form-urlencoded", StandardCharsets.UTF_8));
        List<MediaType> acceptMediaTypes = new ArrayList<MediaType>();
        acceptMediaTypes.add(new MediaType("application", "json", StandardCharsets.UTF_8));
        headers.setAccept(acceptMediaTypes);
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String,String>();
        formData.add("grant_type", GRANT_TYPE_JWT_BEARER);
        formData.add("assertion", token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        
        ResponseEntity<OAuth2AccessToken> response = this.machineClient.postForEntity(baseUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        //verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        System.out.println("Token: " + accessToken + "--------Token Type:" + accessToken.getTokenType());
        Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) claims.get("authorities");
        List<String> scopes = (List<String>) claims.get("scope");
        Assert.assertTrue(scopes.contains("machine.m1.admin"));
        Assert.assertTrue(authorities.contains("machine.m1.admin"));
        Assert.assertEquals(ISSUER_ID, claims.get("sub"));
        Assert.assertEquals(ISSUER_ID, claims.get("client_id"));
        Assert.assertEquals(GRANT_TYPE_JWT_BEARER, claims.get("grant_type"));
        Assert.assertEquals("http://localhost:8080/uaa/oauth/token", claims.get("iss"));
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}

























