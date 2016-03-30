package org.cloudfoundry.identity.uaa.integration.feature;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.MockClientAssertionHeader;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantIT {

    /*
     * Copy PKCS1_HEADER_SIGNING_KEY into a file, i.e., pr.key
     * openssl pkcs8 -topk8 -inform pem -in pr.key -outform pem -nocrypt -out prkey.pem
     * Copy content of prkey.pem into PKCS8_HEADER_SIGNING_KEY removing "-----BEGIN PRIVATE KEY-----" header and 
     * "-----END PRIVATE KEY-----" footer
     */
    static final String PKCS8_HEADER_SIGNING_KEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHG8SB4dNAnQku"
            + "JBjlQeaxJIRzQm3etEs5xBtW+ICM6H9VPtUdaUgepdTm3q2FulRuO0+zzXxQRdA7"
            + "zmK5YjxOnkJG5idEVACgYAztXSQjA5QbBeE6BkFjsFD4j47cwVCficWnzPm7nbZF"
            + "sWD5o01AIvJdkuLN1ENUO98qKH8PWec1Q7X1uP3B1nfYy+koNbaWYyTlmSrQFXBL"
            + "JcS+f/BNKUGvacNGFM0+6T4kVrCBlCiw1F92HUSUQmbe2B7zUlJSD80s+wIANRaa"
            + "1GiFpWEgZ2mpLQA/LA7fF0bPvdRjjGQW2ppoqnW8NfD2WMdSRpnI+zCcq7xISu8Z"
            + "1O8gNsp9AgMBAAECggEABTWl4xgxDBnCA9xydUyQN55f2Q3jrKWpDOYp47WbR1Oj"
            + "rUbJ8uNfW4craWeGq1Re8w0oapduxq2adOPlXJ6UErf5eEBhnTnb+FMbzH896He3"
            + "2z7jy1f4Z36h8KOgb5Sopi4qx+iYbIqNP6yyP43zaZivXbpPMn6Pxgy08ywykgXo"
            + "CFk9P9YlOKYOS2WnbShVgVew3Ea4t5xpbOVlHB9GtS43j3k8TZ9DHVYJaXmscltj"
            + "GDJ5DC2bXySwdFHGmorb+6PUsYznizT4N6CBYMEiOs1J3k9BapOH7HPmplqMA7Z0"
            + "BxvPY/NaQmO4LupcCZVTJaMlcMdXpF74NAmv4MiqIQKBgQDJOu7bchThNX+Zp2O5"
            + "bK4ErWERlOuI7O3+U6UfURM3OlBYyeruoNmi88jXQoPzoGR+Mk5E0hBfdV5bDX/+"
            + "G0mqwRXKZrgqcPPFy+nlrrc0hjMT9ginzPtppO/jHQmKT5QuVpginIUoAjmFStji"
            + "u80LytkJA77yOjJEaNE8t6GdZQKBgQCr4a/EBEJyYApjQ1fk4vZa69Mmdx2Td9uq"
            + "KQ8u2N8DYskH7Wr/T0Q1RnN/jIPUE1l1p5i4NPPrBY7jf0NeTegu9jM3Ano/LypG"
            + "t/KddOptcdUKEKJ/xRBHN4mlUYgvGrWto+kQyyigHUSX+kK1fID6MPWSe5F4VIsV"
            + "kYT4xLdTOQKBgC55jfDgyDG7SV0Ta9THZOlvoZuN6VgWYGD8sIYrE2UN8sCO4dN7"
            + "EsivxRLyKcd6o7sBo1IBsgZZ9RDSbV0isEDfl0jHsIEc1TA5iCujzmwzEljp2dXn"
            + "YalkjoLFkg5/kpmhJkHYJGi5Gs/OGYlEFndCwh1y4AbRqgpiqvB6+LiBAoGAfnJQ"
            + "kP6lN2lKGw5O2fbST78Pnkug+X0Cn+MG5WrsXZxN0kQqI9rXje3fSCVCUkFN3c1G"
            + "/7UNAIgdP2W/VOAxgGLk+IIdFuCG1HG8zXNWht9oX7gvI5oAyLOl0nXxnt2ibDSa"
            + "YB1lLK17aebVLpiCdgyQjIvVT9W6YEqmrTBiwZkCgYAKpUQrotet+FxVGFJwPnW1"
            + "jO/92qKZV7NnDhh55buJGTJ19GZ/tBbXoI7ipvN+gMzxE/RuxFrG2TE+LXCJz8Kw"
            + "3uLJiwsoLUo6GD02Jit+JfiBxgcL88QYrzHe6lhSETjFpF4nTAoEVVY55BmMdb5F"
            + "kzEN/tEe/vV/tIU3ztg0Zg==";

    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private final static String ISSUER_ID = "client-d10";
    private final static String DEVICE_ID = "d10";
    private static final String AUDIENCE = "http://localhost:8080/uaa/oauth/token";

    @Value("${integration.test.base_url}")
    private String baseUrl;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    ServerRunning serverRunning = ServerRunning.isRunning();

    private OAuth2RestTemplate adminClient;
    private final RestTemplate tokenRestTemplate = new RestTemplate();

    private HttpHeaders getHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockSignedHeader(DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);
        return headers;
    }

    private void createTestMachineClient() throws Exception {
        // register client for jwt-bearer grant
        this.adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.baseUrl, new String[0], "admin", "adminsecret"));
        BaseClientDetails client = new BaseClientDetails(ISSUER_ID, "none", "uaa.none", OauthGrant.JWT_BEARER,
                CONFIGURED_SCOPE, null);
        IntegrationTestUtils.createClient(this.adminClient.getAccessToken().getValue(), this.baseUrl, client);
    }

    @Test
    public void testJwtBearerGrantForUnknownClient() {
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("authz grant with unknown client did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void testJwtBearerGrantWrongGrantType() throws Exception {
        createTestMachineClient();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.CLIENT_CREDENTIALS);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
        IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
    }

    @Test
    public void testJwtBearerGrantNoAssertionTokenWithBasicAuth() throws Exception {
        createTestMachineClient();

        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantEmptyAssertionToken() throws Exception {
        createTestMachineClient(); // create client assertion header

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, "");
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantNoAssertionToken() throws Exception {
        createTestMachineClient();

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantAndClientGrantSuccess() throws Exception {
        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        doJwtBearerGrantRequest(headers);
    }

    @Test
    public void testJwtBearerGrantAndClientGrantWithBadCreds() throws Exception {
        createTestMachineClient();
        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "notaadmin:notaadminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, 0, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            headers.remove("Authorization");
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        doJwtBearerGrantRequest(getHttpHeaders());
    }

    private void doJwtBearerGrantRequest(HttpHeaders headers) throws Exception {
        createTestMachineClient();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID,
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        // verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        assertAccessToken(accessToken);
        IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
    }

    @Test
    public void testJwtBearerGrantNoDeviceHeader() throws Exception {
        createTestMachineClient();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, new HttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow without client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantEmptyDeviceHeader() throws Exception {
        createTestMachineClient();

        HttpHeaders headers = new HttpHeaders();
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, "");

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with empty client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantIncorrectlySignedDeviceHeader() throws Exception {
        createTestMachineClient();

        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockIncorrectlySignedHeader(DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, DEVICE_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrently signed client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, ISSUER_ID);
        }
    }

    private void assertAccessToken(final OAuth2AccessToken accessToken) {
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        List<String> scopes = (List<String>) claims.get(ClaimConstants.SCOPE);
        Assert.assertTrue(scopes.contains(CONFIGURED_SCOPE));
        Assert.assertEquals(ISSUER_ID, claims.get(ClaimConstants.SUB));
        Assert.assertEquals(ISSUER_ID, claims.get(ClaimConstants.CLIENT_ID));
        Assert.assertEquals(OauthGrant.JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        Assert.assertEquals("http://localhost:8080/uaa/oauth/token", claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String expirationTimestamp = (claims.get(ClaimConstants.EXP)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(expirationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}