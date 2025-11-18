package org.cloudfoundry.identity.uaa.degraded;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.SamlServerConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
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

import static java.time.temporal.ChronoUnit.SECONDS;
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