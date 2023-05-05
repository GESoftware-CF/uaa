package org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.testscripts;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.IntegrationTestRule;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.uilocators.GeSsoIDPlogin;
import org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.uilocators.GeSsoSPlogin;
import org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.utils.Constants;
import org.cloudfoundry.identity.uaa.integration.feature.federatedlogin.utils.IntegrationTestUtilsStage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.*;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate2;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class FederatedLogin {

    public static final String IDP_ENTITY_ID = "cloudfoundry-saml-login";

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();

    //*********Loading all data from constants file**********//
    static String ExpectedUrl = Constants.URL;
    static String GESSO_UserName = Constants.SS0_UserName;
    static String GESSO_Password = Constants.SS0_Password;
    static String IDP_Password = Constants.IDP_Password;
    static String IDP_UserName = Constants.IDP_UserName;

    @Before
    public void clearWebDriverOfCookies() throws Exception {
        samlTestUtils.initialize();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone2.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
    }

    @Before
    public void setup() {
        String token = IntegrationTestUtilsStage.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        ScimGroup group = new ScimGroup(null, "zones.testzone1.admin", null);
        IntegrationTestUtilsStage.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.testzone2.admin", null);
        IntegrationTestUtilsStage.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.uaa.admin", null);
        IntegrationTestUtilsStage.createGroup(token, "", baseUrl, group);
    }

    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(),
                    new byte[]{127, 0, 0, 1})
                    && Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(),
                    new byte[]{127, 0, 0, 1})
                    && Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(),
                    new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @Test
    public void testCrossZoneSamlIntegration() throws Throwable {
        String idpZoneId = "testzone1";
        String idpZoneUrl = baseUrl.replace("localhost", idpZoneId + ".localhost");
        String spZoneId = "testzone2";
        String spZoneUrl = baseUrl.replace("localhost", spZoneId + ".localhost");
        RestTemplate adminClient = getAdminClient();
        RestTemplate identityClient = getIdentityClient();
        //Creating Orch IDP Zone
        IdentityZone idpZone = IntegrationTestUtilsStage.createOrchZone(identityClient, baseUrl, idpZoneId, idpZoneId, null);
        idpZone.getId();
        String idpZoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        //Create user for IDP Admin
        createZoneUser(idpZoneId, idpZoneUserEmail, idpZoneUrl);
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setWantAssertionSigned(true);
        samlConfig.addAndActivateKey("key-1", new SamlKey(key1, passphrase1, certificate1));
        samlConfig.addKey("key-2", new SamlKey(key2, passphrase2, certificate2));
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setSamlConfig(samlConfig);
        //Creating Orch SP Zone
        IdentityZone spZone = IntegrationTestUtilsStage.createOrchZone(identityClient, baseUrl, spZoneId, spZoneId, config);
        //Get Client credentials to for SP Admin token
        String spZoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        //Get IDP meta Data
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createZone1IdpDefinition(IDP_ENTITY_ID);
        //configure IDP with Metadata
        IdentityProvider<SamlIdentityProviderDefinition> idp = getSamlIdentityProvider(spZone.getId(), spZoneAdminToken, samlIdentityProviderDefinition);
        //Get Sp meta data
        SamlServiceProviderDefinition samlServiceProviderDefinition = createZone2SamlSpDefinition("cloudfoundry-saml-login");
        //Configure SP with Metadata
        SamlServiceProvider service = getSamlServiceProvider(idpZone.getId(), spZoneAdminToken, samlServiceProviderDefinition, "testzone2.cloudfoundry-saml-login", "Local SAML SP for testzone2", baseUrl);
        //Login into SP with IDP credentials
        performLogin(idpZone.getId(), idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");
    }

    private RestTemplate getAdminClient() {
        // String[] scopes = {"zones.write"};
        return IntegrationTestUtilsStage.getClientCredentialsTemplate(
                IntegrationTestUtilsStage.getClientCredentialsResource(
                        baseUrl, new String[0], "admin", "adminsecret")
        );
    }

    private RestTemplate getIdentityClient() {
        return IntegrationTestUtilsStage.getClientCredentialsTemplate(
                IntegrationTestUtilsStage.getClientCredentialsResource(
                        baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
    }


    private String getZoneAdminToken(RestTemplate adminClient, String zoneId) {
        String zoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser idpZoneAdminUser = IntegrationTestUtilsStage.createUser(adminClient, baseUrl, zoneAdminEmail, "firstname", "lastname", zoneAdminEmail, true);
        String groupId = IntegrationTestUtilsStage.findGroupId(adminClient, baseUrl, "zones." + zoneId + ".admin");
        //assertThat(groupId, is(notNullValue()));
        IntegrationTestUtilsStage.addMemberToGroup(adminClient, baseUrl, idpZoneAdminUser.getId(), groupId);
        return IntegrationTestUtilsStage.getAccessTokenByAuthCode(
                serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                zoneAdminEmail,
                "secr3T"
        );
    }


    private ScimUser createZoneUser(String idpZoneId, String zoneUserEmail, String zoneUrl) {
        RestTemplate zoneAdminClient = IntegrationTestUtilsStage.getClientCredentialsTemplate(IntegrationTestUtilsStage
                .getClientCredentialsResource(zoneUrl, new String[0], "admin", "adminsecret"));
        return IntegrationTestUtilsStage.createUserWithPhone(zoneAdminClient, zoneUrl, zoneUserEmail, "Dana", "Scully", zoneUserEmail,
                true, "1234567890");
    }

    public SamlIdentityProviderDefinition createZone1IdpDefinition(String alias) {
        return createLocalSamlIdpDefinition(alias, "testzone1");
    }

    public static SamlIdentityProviderDefinition createLocalSamlIdpDefinition(String alias, String zoneId) {
        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/idp/metadata";
        } else {
            url = "http://localhost:8080/uaa/saml/idp/metadata";
        }
        String idpMetaData = getIdpMetadata(url);
        return SamlTestUtils.createLocalSamlIdpDefinition(alias, zoneId, idpMetaData);
    }

    public static String getIdpMetadata(String url) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        HttpEntity<String> getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        return metadataResponse.getBody();
    }

    private IdentityProvider<SamlIdentityProviderDefinition> getSamlIdentityProvider(String spZoneId, String spZoneAdminToken, SamlIdentityProviderDefinition samlIdentityProviderDefinition) {
        IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setIdentityZoneId(spZoneId);
        idp.setType(OriginKeys.SAML);
        idp.setActive(true);
        idp.setConfig(samlIdentityProviderDefinition);
        idp.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        idp.setName("Local SAML IdP for testzone1");
        idp = IntegrationTestUtilsStage.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        return idp;
    }

    public static SamlServiceProviderDefinition createZone2SamlSpDefinition(String alias) {
        return createLocalSamlSpDefinition(alias, "testzone2");
    }

    public static SamlServiceProviderDefinition createLocalSamlSpDefinition(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/" + zoneId + "." + alias;
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias;
        }

        String spMetaData = getIdpMetadata(url);
        SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation(spMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setSingleSignOnServiceIndex(0);
        def.setMetadataTrustCheck(false);
        def.setEnableIdpInitiatedSso(true);
        return def;
    }

    private SamlServiceProvider getSamlServiceProvider(String idpZoneId, String idpZoneAdminToken, SamlServiceProviderDefinition samlServiceProviderDefinition, String entityId, String local_saml_sp_for_testzone2, String baseUrl) {
        SamlServiceProvider sp = new SamlServiceProvider();
        sp.setIdentityZoneId(idpZoneId);
        sp.setActive(true);
        sp.setConfig(samlServiceProviderDefinition);
        sp.setEntityId(entityId);
        sp.setName(local_saml_sp_for_testzone2);
        sp = createOrUpdateSamlServiceProvider(idpZoneAdminToken, baseUrl, sp);
        return sp;
    }

    public static SamlServiceProvider createOrUpdateSamlServiceProvider(String accessToken, String url,
                                                                        SamlServiceProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<SamlServiceProvider> existing = getSamlServiceProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (SamlServiceProvider p : existing) {
                if (p.getEntityId().equals(provider.getEntityId())
                        && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity<SamlServiceProvider> putHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(url + "/saml/service-providers/{id}",
                            HttpMethod.PUT, putHeaders, String.class, provider.getId());
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), SamlServiceProvider.class);
                    }
                }
            }
        }

        HttpEntity<SamlServiceProvider> postHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(url + "/saml/service-providers/{id}", HttpMethod.POST,
                postHeaders, String.class, provider.getId());
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), SamlServiceProvider.class);
        }
        throw new IllegalStateException(
                "Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }


    public static List<SamlServiceProvider> getSamlServiceProviders(String zoneAdminToken, String url, String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> providerGet = client.exchange(url + "/saml/service-providers", HttpMethod.GET, getHeaders,
                String.class);
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<SamlServiceProvider>>() {
                // Do nothing.
            });
        }
        return null;
    }

    public void performLogin(String idpZoneId, String idpZoneUserEmail, String idpZoneUrl, IdentityZone spZone, String spZoneUrl, SamlIdentityProviderDefinition samlIdentityProviderDefinition) {
        GeSsoIDPlogin ssoIdp = new GeSsoIDPlogin(webDriver);
        GeSsoSPlogin ssoSp = new GeSsoSPlogin(webDriver);
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");
        webDriver.get(idpZoneUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/");
        assertEquals(spZone.getName(), webDriver.getTitle());
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        ssoSp.clickOnSignInByGesso();
        try {

            ssoIdp.headLineCheck();

            ssoIdp.enterIDPuserName(idpZoneUserEmail);

            ssoIdp.enterIDPPassword("secr3T");
            //This is modified for branding login.yml changes...
            ssoIdp.clickOnSignIn();
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
            Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
            assertNotNull(afterLogin);
            assertNotNull(afterLogin.getValue());
            assertNotEquals(beforeLogin.getValue(), afterLogin.getValue());
        } catch (Exception e) {
            assertTrue("Http-Artifact binding is not supported", e instanceof NoSuchElementException);

        }
    }
}
