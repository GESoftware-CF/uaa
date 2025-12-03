package org.cloudfoundry.identity.uaa.acceptance;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.MockClientAssertionHeader;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantAT {
    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private final static String DEVICE_ID = "d10";
    private final static String DEVICE_CLIENT_ID = "c1";

    protected final static Logger logger = LoggerFactory.getLogger(JwtBearerGrantAT.class);

    @Value("${ACCEPTANCE_ZONE_URL:}")
    String acceptanceZoneUrl;

    @Value("${KEY_PROVIDER_SERVICE_URL:not-used}")
    String keyProviderServiceUrl;

    @Value("${TOKEN_ISSUER_URL:}")
    String tokenIssuerUrl;

    private OAuth2RestTemplate adminClientRestTemplate;
    private UaaClientDetails identityClient;
    private final RestTemplate tokenRestTemplate = new RestTemplate();
    String assertionTokenAudience;
    String acceptanceTokenIssuer;

    @BeforeEach
    public void beforeEachTest() throws Exception {
        logger.info("=== Setting up test environment ===");
        logger.info("KEY_PROVIDER_SERVICE_URL: {}", keyProviderServiceUrl);
        logger.info("ACCEPTANCE_ZONE_URL: {}", acceptanceZoneUrl);
        logger.info("TOKEN_ISSUER_URL: {}", tokenIssuerUrl);

        Assumptions.assumeTrue(keyProviderServiceUrl != null &&
                keyProviderServiceUrl.trim().startsWith("http"),
                "KEY_PROVIDER_SERVICE_URL must be set and start with http");
        Assumptions.assumeTrue(acceptanceZoneUrl != null &&
                acceptanceZoneUrl.trim().startsWith("http"),
                "ACCEPTANCE_ZONE_URL must be set and start with http");

        logger.info("Getting admin client credentials template...");
        this.adminClientRestTemplate = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.acceptanceZoneUrl, new String[0], "admin", "acceptance-test"));
        logger.info("Admin client access token obtained: {}",
                this.adminClientRestTemplate.getAccessToken() != null ? "yes" : "no");

        this.instantiateIdentityClient();
        this.assertionTokenAudience = this.acceptanceZoneUrl + "/oauth/token";
        logger.info("Assertion token audience set to: {}", this.assertionTokenAudience);

        if (this.tokenIssuerUrl.isEmpty()) {
            this.acceptanceTokenIssuer = this.acceptanceZoneUrl + "/oauth/token";
            logger.info("Token issuer URL not provided, using acceptance zone URL: {}", this.acceptanceTokenIssuer);
        } else {
            this.acceptanceTokenIssuer = this.tokenIssuerUrl;
            logger.info("Token issuer URL set to: {}", this.acceptanceTokenIssuer);
        }

        createUaaClientForDevice(DEVICE_ID);
        logger.info("=== Test environment setup complete ===");
    }

    @AfterEach
    public void afterEachTest() throws Exception {
        logger.info("=== Cleaning up test environment ===");
        logger.info("Deleting client: {}", DEVICE_CLIENT_ID);
        try {
            IntegrationTestUtils.deleteClient(this.adminClientRestTemplate, this.acceptanceZoneUrl, DEVICE_CLIENT_ID);
            logger.info("Successfully deleted client: {}", DEVICE_CLIENT_ID);
        } catch (Exception e) {
            logger.warn("Failed to delete client: {}", DEVICE_CLIENT_ID, e);
            throw e;
        }
        logger.info("=== Test cleanup complete ===");
    }

    private void instantiateIdentityClient() {
        this.identityClient = new UaaClientDetails();
        this.identityClient.setClientId("identity");
        this.identityClient.setClientSecret("identitysecret");
    }

    private HttpHeaders getHttpHeaders() {
        logger.info("Creating HTTP headers with Predix-Client-Assertion");
        HttpHeaders headers = new HttpHeaders();
        long currentTime = System.currentTimeMillis() / 1000;
        String assertionHeader = new MockClientAssertionHeader().mockSignedHeader(currentTime, DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);
        logger.info("Created Predix-Client-Assertion header for device: {}, tenant: {}, timestamp: {}",
                DEVICE_ID, TENANT_ID, currentTime);
        logger.info("Assertion header (first 50 chars): {}",
                assertionHeader.substring(0, Math.min(50, assertionHeader.length())));
        return headers;
    }

    private void createUaaClientForDevice(final String deviceId) throws Exception {
        logger.info("Creating UAA client for device: {}", deviceId);
        // register client for jwt-bearer grant
        UaaClientDetails client = new UaaClientDetails(DEVICE_CLIENT_ID, "none", "uaa.none", GRANT_TYPE_JWT_BEARER,
                CONFIGURED_SCOPE, null);
        // authorize device for test client
        client.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, deviceId);
        logger.info("Client details - ID: {}, Authorized Grants: {}, Scope: {}, Allowed Device: {}",
                DEVICE_CLIENT_ID, GRANT_TYPE_JWT_BEARER, CONFIGURED_SCOPE, deviceId);

        IntegrationTestUtils.createClient(this.adminClientRestTemplate.getAccessToken().getValue(), this.acceptanceZoneUrl, client);
        logger.info("Successfully created UAA client: {}", DEVICE_CLIENT_ID);
    }

    @Test
    public void testJwtBearerGrantAndClientGrantSuccess() throws Exception {
        logger.info("=== Starting testJwtBearerGrantAndClientGrantSuccess ===");
        logger.info("Acceptance Zone URL: {}", this.acceptanceZoneUrl);
        logger.info("Device Client ID: {}", DEVICE_CLIENT_ID);
        logger.info("Device ID: {}", DEVICE_ID);
        logger.info("Tenant ID: {}", TENANT_ID);

        HttpHeaders headers = getHttpHeaders();
        logger.info("Initial headers created with Predix-Client-Assertion");

        String clientCreds = "admin:acceptance-test";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        logger.info("Added Basic Authorization header for admin:acceptance-test");
        logger.info("Request headers: {}", headers.keySet());

        doJwtBearerGrantRequest(headers, this.acceptanceZoneUrl, this.identityClient, new MockAssertionToken());
        logger.info("=== testJwtBearerGrantAndClientGrantSuccess completed successfully ===");
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        logger.info("=== Starting testJwtBearerGrantSuccess ===");
        logger.info("Testing JWT bearer grant WITHOUT additional Basic auth header");
        doJwtBearerGrantRequest(getHttpHeaders(), this.acceptanceZoneUrl, this.identityClient, new MockAssertionToken());
        logger.info("=== testJwtBearerGrantSuccess completed successfully ===");
    }

    private void doJwtBearerGrantRequest(final HttpHeaders headers, final String uaaUrl, final UaaClientDetails client, MockAssertionToken assertionToken) throws Exception {
        logger.info("=== doJwtBearerGrantRequest started ===");
        logger.info("UAA URL: {}", uaaUrl);
        logger.info("Client ID: {}", client.getClientId());
        logger.info("Assertion Token Audience: {}", assertionTokenAudience);

        // create bearer token
        String token = assertionToken.mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, assertionTokenAudience);
        logger.info("Created mock assertion token for device: {} with client: {}", DEVICE_ID, DEVICE_CLIENT_ID);
        logger.info("Assertion token (first 50 chars): {}", token.substring(0, Math.min(50, token.length())));

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        logger.info("<<<<<<<<<<<<<<<<<<<<Use JWT Grant to Exchange the token>>>>>>>>>>>>>"+token);
        formData.add(ASSERTION, token);

        logger.info("Form data prepared - grant_type: {}", GRANT_TYPE_JWT_BEARER);
        logger.info("Request headers being sent: {}", headers);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        OAuth2AccessToken accessToken;
        logger.info("Sending POST request to: {}/oauth/token", uaaUrl);
        try {
            ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(uaaUrl + "/oauth/token",
                    requestEntity, OAuth2AccessToken.class);
            logger.info("Received response with status: {}", response.getStatusCode());

            // verify access token received
            accessToken = response.getBody();
            logger.info("Access token retrieved: {}", accessToken != null ? "present" : "null");
            if (accessToken != null) {
                logger.info("Access token type: {}", accessToken.getTokenType());
                logger.info("Access token expires in: {} seconds", accessToken.getExpiresIn());
            }

            assertAccessToken(accessToken);
            logger.info("Access token assertions passed");
        } catch (Exception e) {
            logger.error("Failed to get access token from {}/oauth/token", uaaUrl, e);
            logger.error("Request headers were: {}", headers);
            logger.error("Form data was: grant_type={}, assertion={}", GRANT_TYPE_JWT_BEARER, token.substring(0, Math.min(100, token.length())));
            throw e;
        }

        MultiValueMap<String, String> tokenFormData = new LinkedMultiValueMap<>();
        tokenFormData.add("token", accessToken.getValue());

        String clientCreds = client.getClientId() + ":" + client.getClientSecret();
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.set("Authorization", "Basic " + base64ClientCreds);

        logger.info("Checking token with client credentials: {}", client.getClientId());

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(this.acceptanceZoneUrl + "/check_token",
                HttpMethod.POST, new HttpEntity<>(tokenFormData, headers), Map.class);
        logger.info("Check token response status: {}", checkTokenResponse.getStatusCode());
        assertEquals(HttpStatus.OK, checkTokenResponse.getStatusCode());
        logger.info("=== doJwtBearerGrantRequest completed successfully ===");
    }

    private void assertAccessToken(final OAuth2AccessToken accessToken) {
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        logger.info(accessToken.toString());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        List<String> scopes = (List<String>) claims.get(ClaimConstants.SCOPE);
        assertTrue(scopes.contains(CONFIGURED_SCOPE));
        assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.SUB));
        assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.CLIENT_ID));
        assertEquals(GRANT_TYPE_JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        assertEquals(this.acceptanceTokenIssuer, claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String expirationTimestamp = (claims.get(ClaimConstants.EXPIRY_IN_SECONDS)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        assertTrue(Long.parseLong(expirationTimestamp) > currentTimestamp);
        assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        assertEquals("bearer", accessToken.getTokenType());
        assertFalse(accessToken.isExpired());
    }
}
