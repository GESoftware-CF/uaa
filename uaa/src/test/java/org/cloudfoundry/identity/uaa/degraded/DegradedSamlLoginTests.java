package org.cloudfoundry.identity.uaa.degraded;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.SamlServerConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static java.time.temporal.ChronoUnit.SECONDS;
import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.cloudfoundry.identity.uaa.login.InvitationsServiceMockMvcTests.REDIRECT_URI;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.provider.token.AccessTokenConverter.CLIENT_ID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
public class DegradedSamlLoginTests {

    private static final String SAML_USERNAME = "samluser1";
    private static final String SAML_PASSWORD = "SamlUser10@";
    private static final String ZONE_AUTHCODE_CLIENT_ID = "exampleClient";
    private static final String ZONE_AUTHCODE_CLIENT_SECRET = "secret";
    public static final String ZONE_ADMIN = "admin";
    @Value("${ZONE_ADMIN_SECRET:adminsecret}")
    String zoneAdminSecret;

    @Value("${PUBLISHED_HOST:predix-uaa-integration}")
    String publishedHost;

    @Value("${CF_DOMAIN:run.aws-usw02-dev.ice.predix.io}")
    String cfDomain;

    @Value("${PUBLISHED_DOMAIN:#{null}}")
    String publishedDomain;

    @Value("${PROTOCOL:#{null}}")
    String protocol;

    @Value("${BASIC_AUTH_CLIENT_ID:app}")
    String basicAuthClientId;

    @Value("${BASIC_AUTH_CLIENT_SECRET:appclientsecret}")
    String basicAuthClientSecret;

    @Autowired
    RestOperations restOperations;

    @Autowired
    public Environment environment;

    @Autowired
    UaaWebDriver webDriver;

    protected final static Logger logger = LoggerFactory.getLogger(DegradedSamlLoginTests.class);
    private final static String zoneSubdomain = "test-app-zone";
    private String baseUrl;
    private String testRedirectUri;
    private String zoneAdminToken;
    private String baseUaaZoneHost;
    @Autowired
    private SamlServerConfig samlServerConfig;

    @BeforeEach
    public void setup() throws Exception {
        if (StringUtils.hasText(publishedDomain)) {
            baseUaaZoneHost = publishedDomain;
        } else {
            baseUaaZoneHost = Boolean.valueOf(environment.getProperty("RUN_AGAINST_CLOUD")) ? (publishedHost + "." + cfDomain) : "localhost:8080/uaa";
        }
        if (StringUtils.hasText(protocol)) {
            protocol = protocol.contains("://") ? protocol : protocol + "://";
        } else {
            protocol = Boolean.valueOf(environment.getProperty("RUN_AGAINST_CLOUD")) ? "https://" : "http://";
        }
        baseUrl = protocol + zoneSubdomain + "." + baseUaaZoneHost;
        testRedirectUri = protocol + "www.example.com";
        zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, ZONE_ADMIN, zoneAdminSecret);
    }

    @Test
    void testScimResourcesReadOnly() throws Exception {
        ScimGroup group = IntegrationTestUtils.getGroup(zoneAdminToken, null, baseUrl, "uaa.admin");
        assertEquals("uaa.admin", group.getDisplayName());

        //Test Degraded mode prevents Write operation
        ScimGroup scimGroup = new ScimGroup(null, "example.group", "test-app-zone");
        try {
            IntegrationTestUtils.createGroup(zoneAdminToken, null, baseUrl, scimGroup);
            Assertions.fail("Group creation should not be allowed");
        } catch (HttpServerErrorException e) {
            assertThat(e.getMessage(), Matchers.containsString("503"));
        }
    }

    @Test
    void testGetTokenKey() {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        HttpEntity<?> getHeaders = new HttpEntity<>(headers);
        ResponseEntity<Map> tokenKeyGet = restTemplate.exchange(
                baseUrl + "/token_key",
                HttpMethod.GET,
                getHeaders,
                Map.class
        );
        assertEquals(HttpStatus.OK, tokenKeyGet.getStatusCode());
    }

    @Test
    public void testIdpsReadOnly() {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> providerGet = client.exchange(
                baseUrl + "/identity-providers",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        assertEquals(HttpStatus.OK, providerGet.getStatusCode());

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = IntegrationTestUtils.createSimplePHPSamlIDP("simplesamlphp", "test-app-zone", samlServerConfig.getSamlServerUrl());
        samlIdentityProviderDefinition.setAddShadowUserOnLogin(true);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("exampleIdp");

        try {
            headers = new LinkedMultiValueMap<>();
            headers.add("Accept", APPLICATION_JSON_VALUE);
            headers.add("Authorization", "bearer "+ zoneAdminToken);
            headers.add("Content-Type", APPLICATION_JSON_VALUE);
            HttpEntity httpEntity = new HttpEntity(provider, headers);
            ResponseEntity<String> providerPost = client.exchange(
                    baseUrl + "/identity-providers",
                    HttpMethod.POST,
                    httpEntity,
                    String.class
            );
            Assertions.fail("Idp creation should not be allowed" + providerPost.getStatusCode() +" : body:" +  providerPost.getBody());
        } catch (HttpServerErrorException e) {
            assertThat(e.getMessage(), Matchers.containsString("503"));
        }
    }

    @Test
    void testPasswordTokenAndCheckToken() {
        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("username", "marissa");
        postBody.add("password", "KOala12@");
        postBody.add(GRANT_TYPE, "password");
        postBody.add(RESPONSE_TYPE, "token");
        postBody.add("token_format", "opaque");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);
        headers.set("Authorization", getAuthorizationHeader(basicAuthClientId, basicAuthClientSecret));

        ResponseEntity<Map> tokenResponse = new RestTemplate().exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), Map.class);
        assertThat(tokenResponse.getStatusCode().value(), Matchers.equalTo(200));

        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken.getValue());

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals("marissa", checkTokenResponse.getBody().get("user_name"));
    }

    @Test
    void testImplicitTokenAndCheckToken() {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/oauth/authorize?client_id=cf&response_type=token&redirect_uri=" + testRedirectUri +"/cf");
        webDriver.manage().timeouts().pageLoadTimeout(Duration.of(20, SECONDS));
        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("login"));
        logger.info(webDriver.getCurrentUrl());
        webDriver.findElement(By.xpath("//title[contains(text(), '" + zoneSubdomain + "')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("KOala12@");
        webDriver.findElement(By.xpath("//input[@type='submit']")).click();

        //Ensure the browser/webdriver processes all the flows
        webDriver.manage().timeouts().implicitlyWait(Duration.of(20, SECONDS));
        //Get the http archive logs
        String requestUrl = webDriver.getCurrentUrl();
        // logger.info("Current page: {}", webDriver.getPageSource());
        logger.info("request url: {}", requestUrl);
        // Changing to https since the latest chrome driver automatically changing http to https. Unable to disable it.
        assertThat(requestUrl, Matchers.startsWith("https://www.example.com/cf#token_type=bearer&access_token="));
        String tokenprefixedString = requestUrl.split("access_token=")[1];
        String accessToken = tokenprefixedString.split("&")[0];

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken);

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);
        headers.set("Authorization", getAuthorizationHeader(basicAuthClientId, basicAuthClientSecret));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals("marissa", checkTokenResponse.getBody().get("user_name"));
    }

    @Test
    void testOidcSamlAuthcodeTokenAndCheckToken() throws Exception {
        // Verify setup before running test
        logger.info("=== Verifying test-platform-zone configuration ===");
        verifyTestPlatformZoneSetup();
        logger.info("=== Starting OIDC SAML auth code flow ===");
        doOidcSamlAuthCodeFlow("/oauth/authorize?client_id=" + ZONE_AUTHCODE_CLIENT_ID + "&response_type=code&redirect_uri=" + testRedirectUri);
    }

    private void verifyTestPlatformZoneSetup() {
        try {
            String platformZoneUrl = protocol + "test-platform-zone." + baseUaaZoneHost;
            logger.info("Verifying configuration at: {}", platformZoneUrl);

            String platformZoneToken = IntegrationTestUtils.getClientCredentialsToken(platformZoneUrl, ZONE_ADMIN, zoneAdminSecret);

            RestTemplate client = new RestTemplate();
            MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            headers.add("Accept", APPLICATION_JSON_VALUE);
            headers.add("Authorization", "bearer " + platformZoneToken);
            HttpEntity<?> getHeaders = new HttpEntity<>(headers);

            // Check IDPs
            ResponseEntity<String> idpsResponse = client.exchange(
                    platformZoneUrl + "/identity-providers",
                    HttpMethod.GET,
                    getHeaders,
                    String.class
            );

            logger.info("test-platform-zone IDPs response status: {}", idpsResponse.getStatusCode());
            String idpsBody = idpsResponse.getBody();

            if (idpsBody != null) {
                boolean hasSamlIdp = idpsBody.contains("test-saml-zone-idp");
                boolean hasEmailDomain = idpsBody.contains("ge.com");
                logger.info("✓ SAML IDP 'test-saml-zone-idp' present: {}", hasSamlIdp);
                logger.info("✓ Email domain 'ge.com' configured: {}", hasEmailDomain);

                if (!hasSamlIdp) {
                    logger.error("SETUP ISSUE: SAML IDP 'test-saml-zone-idp' NOT found!");
                    logger.error("Available IDPs: {}", idpsBody);
                    Assertions.fail("Setup verification failed: SAML IDP 'test-saml-zone-idp' not configured. Did setupDegradedTests.sh run successfully?");
                }

                if (!hasEmailDomain) {
                    logger.warn("WARNING: Email domain 'ge.com' not found in IDP config - discovery may fail");
                }
            }

            // Check OIDC client
            try {
                ResponseEntity<String> clientResponse = client.exchange(
                        platformZoneUrl + "/oauth/clients/oidcClient",
                        HttpMethod.GET,
                        getHeaders,
                        String.class
                );
                logger.info("✓ oidcClient exists: {}", clientResponse.getStatusCode());
                String clientBody = clientResponse.getBody();
                if (clientBody != null && clientBody.contains("test-saml-zone-idp")) {
                    logger.info("✓ oidcClient allows test-saml-zone-idp provider");
                }
            } catch (Exception e) {
                logger.warn("Could not verify oidcClient (may be normal): {}", e.getMessage());
            }

            logger.info("=== Setup verification complete ===");

        } catch (Exception e) {
            logger.error("Failed to verify test-platform-zone setup", e);
            Assertions.fail("Setup verification failed: " + e.getMessage() + ". Ensure setupDegradedTests.sh ran successfully before enabling degraded mode.");
        }
    }

    private void doOidcSamlAuthCodeFlow(String firstUrl) throws Exception {
        Assertions.assertTrue(findZoneInUaa(), "Expected app zone subdomain to exist");
        logger.info("OIDC base url {}", baseUrl);
        webDriver.get(baseUrl + firstUrl);
        //idp_discovery in test-platform-zone
        logger.info("Current page url: {}", webDriver.getCurrentUrl());
        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("test-platform-zone"));
        logger.info("Discovery page: {}", webDriver.getPageSource());
        String emailToEnter = SAML_USERNAME + "@ge.com";
        logger.info("Entering email for IDP discovery: {}", emailToEnter);
        webDriver.findElement(By.name("email")).clear();
        webDriver.findElement(By.name("email")).sendKeys(emailToEnter);

        logger.info("Clicking 'Next' button to trigger IDP discovery based on @ge.com domain");
        webDriver.findElement(By.cssSelector(".form-group input[value='Next']")).click();

        // Wait for navigation
        webDriver.manage().timeouts().implicitlyWait(Duration.of(20, SECONDS));

        String urlAfterNext = webDriver.getCurrentUrl();
        String pageAfterNext = webDriver.getPageSource();
        logger.info("After clicking Next - URL: {}", urlAfterNext);
        logger.info("After clicking Next - Page title: {}", webDriver.getTitle());

        // Check if we're on SAML login page or still on discovery page
        boolean hasSamlRequest = pageAfterNext.contains("SAMLRequest") || urlAfterNext.contains("SAMLRequest");
        boolean hasUsernameField = pageAfterNext.contains("name=\"username\"");
        boolean hasPasswordField = pageAfterNext.contains("name=\"password\"");
        boolean isTestSamlZone = urlAfterNext.contains("test-saml-zone");
        boolean isSimpleSamlPhp = urlAfterNext.contains("simplesamlphp");
        boolean isDiscoveryPage = urlAfterNext.contains("idp_discovery") || urlAfterNext.contains("/discovery");

        logger.info("Page analysis - hasSamlRequest: {}, hasUsernameField: {}, hasPasswordField: {}",
                    hasSamlRequest, hasUsernameField, hasPasswordField);
        logger.info("Page analysis - isTestSamlZone: {}, isSimpleSamlPhp: {}, isDiscoveryPage: {}",
                    isTestSamlZone, isSimpleSamlPhp, isDiscoveryPage);

        if (isDiscoveryPage) {
            logger.error("ERROR: Still on discovery page - IDP matching failed!");
            logger.error("Page HTML (first 1000 chars): {}", pageAfterNext.substring(0, Math.min(1000, pageAfterNext.length())));
            Assertions.fail("IDP discovery failed: still on discovery page after clicking Next. Email domain @ge.com should match test-saml-zone-idp");
        }

        if (!hasSamlRequest && !isTestSamlZone && !isSimpleSamlPhp) {
            logger.error("ERROR: Did not redirect to SAML IDP");
            logger.error("Expected: SAML request OR test-saml-zone OR simplesamlphp");
            logger.error("Actual URL: {}", urlAfterNext);
            logger.error("Page snippet: {}", pageAfterNext.substring(0, Math.min(1000, pageAfterNext.length())));
            Assertions.fail("IDP discovery did not redirect to SAML zone. URL: " + urlAfterNext);
        }

        logger.info("✓ Successfully redirected to SAML login flow");
        logger.info("Full page after Next: {}", pageAfterNext);

        // Now find and fill the login form
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(SAML_USERNAME);
        webDriver.findElement(By.name("password")).sendKeys(SAML_PASSWORD);
        logger.info("Username entered {}", webDriver.findElement(By.name("username")).getAttribute("value"));
        logger.info("Password Entered {}", webDriver.findElement(By.name("password")).getAttribute("value"));
        webDriver.findElement(By.xpath("//input[@type='submit']")).click();

        //Ensure the browser/webdriver processes all the flows
        webDriver.manage().timeouts().implicitlyWait(Duration.of(20, SECONDS));
        logger.info("Login failure page: {}", webDriver.getPageSource());

        String lastRequestUrl = webDriver.getCurrentUrl();
        logger.info("last request url: " + lastRequestUrl);
        assertThat(lastRequestUrl, Matchers.containsString(testRedirectUri));
        String authcode = lastRequestUrl.split("code=")[1];
        logger.info("AuthCode is: ",authcode);

        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add(CLIENT_ID, ZONE_AUTHCODE_CLIENT_ID);
        postBody.add(CLIENT_SECRET, ZONE_AUTHCODE_CLIENT_SECRET);
        postBody.add("code", authcode);
        postBody.add(GRANT_TYPE, "authorization_code");
        postBody.add(REDIRECT_URI, testRedirectUri);
        postBody.add(RESPONSE_TYPE, "token");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);

        ResponseEntity<Map> tokenResponse = new RestTemplate().exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), Map.class);
        assertThat(tokenResponse.getStatusCode().value(), Matchers.equalTo(200));

        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken.getValue());

        headers.set("Authorization", getAuthorizationHeader(ZONE_ADMIN, zoneAdminSecret));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals(SAML_USERNAME, checkTokenResponse.getBody().get("user_name"));

    }

    private String getAuthorizationHeader(String username, String password) {
        String credentials = String.format("%s:%s", username, password);
        return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
    }

    private boolean findZoneInUaa() {
        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], ZONE_ADMIN, zoneAdminSecret));
        ResponseEntity<String> responseEntity = zoneAdminClient.getForEntity(baseUrl + "/login", String.class);

        logger.info("response body: " + responseEntity.getStatusCode());
        return responseEntity.getStatusCode() == HttpStatus.OK;
    }
}
