package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.EmailAccountCreationService;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.test.MockMvcTestClient;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.PredictableGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.Consent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.csrf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

@DefaultTestContext
class AccountsControllerMockMvcTests {

    private static final String ACCOUNT_CREATE_MESSAGE = "Create your Predix account";
    private static final String ACCOUNT_OTHER_ZONE_CREATE_MESSAGE = "Create your account";
    private static final String UAA_AUTHOR = "Predix";
    private static final String UAA_AUTHOR_ADDRESS = "<admin@localhost>";
    private static final PredictableGenerator PREDICTABLE_GENERATOR = new PredictableGenerator();
    private static final String LOGIN_REDIRECT = "/login?success=verify_success";
    private static final String USER_PASSWORD = "secr3T";
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private String userEmail;
    private MockMvcTestClient mockMvcTestClient;
    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    private TestClient testClient;
    @Autowired
    private FakeJavaMailSender fakeJavaMailSender;
    private JavaMailSender originalEmailSender;
    @Autowired
    private EmailService emailService;

    @BeforeEach
    void setUp() {
        testClient = new TestClient(mockMvc);

        originalEmailSender = emailService.getMailSender();
        emailService.setMailSender(fakeJavaMailSender);

        userEmail = "user" + new AlphanumericRandomValueStringGenerator().generate() + "@example.com";
        IdentityZoneHolder.setProvisioning(webApplicationContext.getBean(IdentityZoneProvisioning.class));

        mockMvcTestClient = new MockMvcTestClient(mockMvc);
    }

    private void setProperty(String name, String value) {
        StandardServletEnvironment env = (StandardServletEnvironment) webApplicationContext.getEnvironment();
        MockPropertySource mockPropertySource = new MockPropertySource();
        mockPropertySource.setProperty(name, value);
        env.getPropertySources().addFirst(mockPropertySource);
        assertThat(webApplicationContext.getEnvironment().getProperty(name)).isEqualTo(value);
    }

    @AfterEach
    void clearEmails() {
        emailService.setMailSender(originalEmailSender);
        fakeJavaMailSender.clearMessage();
    }

    @Test
    void createActivationEmailPage() throws Exception {
        mockMvc.perform(get("/create_account"))
                .andExpect(content().string(containsString(ACCOUNT_CREATE_MESSAGE)));
    }

    @Test
    void createActivationEmailPageWithinZone() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext,
                                                                 IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);
        MockMvcUtils.updateZone(mockMvc, zone);

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(content().string(containsString(ACCOUNT_OTHER_ZONE_CREATE_MESSAGE)));
    }

    @Test
    void activationEmailSentPage() throws Exception {
        mockMvc.perform(get("/accounts/email_sent"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(ACCOUNT_CREATE_MESSAGE)))
                .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"));
    }

    @Test
    void activationEmailSentPageWithinZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(get("/accounts/email_sent")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(ACCOUNT_OTHER_ZONE_CREATE_MESSAGE)))
            .andExpect(xpath("//input[@disabled='disabled']/@value").string("Email successfully sent"));
    }

    @Test
    void pageTitle() throws Exception {
        mockMvc.perform(get("/create_account"))
            .andExpect(content().string(containsString("<title>Predix</title>")));
    }

    @Test
    void pageTitleWithinZone() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(content().string(containsString("<title>" + zone.getName() + "</title>")));
    }

    @Disabled("predix branding does not have this image.")
    @Test
    void createAccountWithDisableSelfService() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);

        MockMvcUtils.createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, getUaaBaseClientDetails(), zone, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(model().attribute("error_message_code", "self_service_create_account_disabled"))
                .andExpect(view().name("error"))
                .andExpect(status().isNotFound());
    }

    @Test
    void disableSelfServiceCreateAccountPost() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);

        MockMvcUtils.createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, getUaaBaseClientDetails(), zone, IdentityZoneHolder.getCurrentZoneId());

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                        .param("email", userEmail)
                        .param("password", "secr3T")
                        .param("password_confirmation", "secr3T"))
                .andExpect(model().attribute("error_message_code", "self_service_create_account_disabled"))
                .andExpect(view().name("error"))
                .andExpect(status().isNotFound());
    }

    @Disabled("predix branding does not have this image.")
    @Test
    void defaultZoneLogoNull_useAssetBaseUrlImage() throws Exception {
        mockMvc.perform(get("/create_account"))
                .andExpect(content().string(containsString("background-image: url(/resources/oss/images/product-logo.png);")));
    }

    @Test
    void zoneLogoNull_doNotDisplayImage() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(content().string(not(containsString("background-image: url(/resources/oss/images/product-logo.png);"))));
    }

    @Test
    void creatingAnAccount() throws Exception {
        setPredictableGenerator();

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", "secr3T")
                        .param("password_confirmation", "secr3T"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        JdbcScimUserProvisioning scimUserProvisioning = webApplicationContext.getBean(JdbcScimUserProvisioning.class);
        ScimUser scimUser = scimUserProvisioning.query("userName eq '" + userEmail + "' and origin eq '" + OriginKeys.UAA + "'", IdentityZoneHolder.get().getId()).getFirst();
        assertThat(scimUser.isVerified()).isFalse();

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void creatingAnAccountWithAnEmptyClientId() throws Exception {
        setPredictableGenerator();

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", "secr3T")
                        .param("password_confirmation", "secr3T")
                        .param("client_id", ""))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void creatingAnAccountWithClientRedirect() throws Exception {
        createAccount("http://redirect.uri/client", "http://redirect.uri/client");
    }

    @Test
    void creatingAnAccountWithFallbackClientRedirect() throws Exception {
        createAccount("http://redirect.uri/fallback", null);
    }

    @Test
    void creatingAnAccountWithNoClientRedirect() throws Exception {
        setPredictableGenerator();

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", "secr3T")
                        .param("password_confirmation", "secr3T"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        FakeJavaMailSender.MimeMessageWrapper message = fakeJavaMailSender.getSentMessages().getFirst();
        assertThat(message.getContentString()).contains(UAA_AUTHOR);
        assertThat(message.getMessage().getHeader("From")).contains(UAA_AUTHOR + " " + UAA_AUTHOR_ADDRESS);

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void creatingAnAccountInAnotherZoneWithNoClientRedirect() throws Exception {
        String subdomain = "mysubdomain2";
        setPredictableGenerator();

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName(subdomain + "zone");
        identityZone.setId(new AlphanumericRandomValueStringGenerator().generate());

        String zonesCreateToken = mockMvcTestClient.getOAuthAccessToken("identity", "identitysecret", "client_credentials", "zones.write");
        mockMvc.perform(post("/identity-zones")
                        .header("Authorization", "Bearer " + zonesCreateToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);
        MockMvcUtils.updateZone(mockMvc, identityZone);
        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                        .param("email", userEmail)
                        .param("password", USER_PASSWORD)
                        .param("password_confirmation", USER_PASSWORD))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        FakeJavaMailSender.MimeMessageWrapper message = fakeJavaMailSender.getSentMessages().getFirst();
        String link = mockMvcTestClient.extractLink(message.getContentString());
        assertThat(message.getContentString()).contains(subdomain + "zone");
        assertThat(message.getMessage().getHeader("From")).contains(subdomain + "zone " + UAA_AUTHOR_ADDRESS);
        assertThat(message.getContentString()).doesNotContain("Cloud Foundry");
        assertThat(message.getContentString()).doesNotContain("Pivotal");
        assertThat(hasLength(link)).isTrue();
        assertThat(link).contains(subdomain + ".localhost");

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get())
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        MvcResult mvcResult = loginWithAccount(subdomain)
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void creatingAnAccountInAnotherZoneWithClientRedirect() throws Exception {
        String subdomain = "mysubdomain1";
        setPredictableGenerator();

        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName(subdomain);
        identityZone.setId(new AlphanumericRandomValueStringGenerator().generate());

        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext,
                                                          getUaaBaseClientDetails(), IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);
        MockMvcUtils.updateZone(mockMvc, zone);
        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", "secr3T")
                        .param("password_confirmation", "secr3T")
                        .param("client_id", "myzoneclient")
                        .param("redirect_uri", "http://myzoneclient.example.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        FakeJavaMailSender.MimeMessageWrapper message = fakeJavaMailSender.getSentMessages().getFirst();
        String link = mockMvcTestClient.extractLink(message.getContentString());
        assertThat(hasLength(link)).isTrue();
        assertThat(link).contains(subdomain + ".localhost");

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get())
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(redirectedUrl(LOGIN_REDIRECT + "&form_redirect_uri=http://myzoneclient.example.com"))
                .andReturn();

        MvcResult mvcResult = loginWithAccount(subdomain)
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    private UaaClientDetails getUaaBaseClientDetails() {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("myzoneclient");
        clientDetails.setClientSecret("myzoneclientsecret");
        clientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        clientDetails.setRegisteredRedirectUri(Collections.singleton("http://myzoneclient.example.com"));
        return clientDetails;
    }

    @Disabled("user verification is disabled")
    @Test
    void redirectToSavedRequest_ifPresent() throws Exception {
        MockHttpSession session = MockMvcUtils.getSavedRequestSession();

        setPredictableGenerator();

        MockMvcUtils.getCreateAccountForm(mockMvc, session);

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .param("email", "testuser@test.org")
                        .param("password", "test-password")
                        .param("password_confirmation", "test-password"))
                .andExpect(redirectedUrl("accounts/email_sent"));

        mockMvc.perform(get("/verify_user")
                        .session(session)
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT))
                .andReturn();

        assertThat(SessionUtils.getSavedRequestSession(session).getRedirectUrl()).isNotNull();
    }

    @Test
    void ifInvalidOrExpiredCode_goTo_createAccountDefaultPage() throws Exception {
        mockMvc.perform(get("/verify_user")
                        .param("code", "expired-code"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("accounts/link_prompt"))
                .andExpect(xpath("//a[text()='here']/@href").string("/create_account"));
    }

    @Test
    void ifInvalidOrExpiredCode_withNonDefaultSignupLinkProperty_goToNonDefaultSignupPage() throws Exception {
        String signUpLink = "http://mypage.com/signup";

        setProperty("links.signup", signUpLink);

        mockMvc.perform(get("/verify_user")
                        .param("code", "expired-code"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("accounts/link_prompt"))
                .andExpect(xpath("//a[text()='here']/@href").string(signUpLink));
    }

    @Test
    void consentIfConfiguredDisplaysConsentTextAndLink() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        String consentLink = "http://google.com";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
                randomZoneSubdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        zone.getConfig().getBranding().getConsent().setLink(consentLink);
        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);

        MockMvcUtils.updateZone(mockMvc, zone);

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost")))
                .andExpect(content().string(containsString(consentText)))
                .andExpect(content().string(containsString(consentLink)));
    }

    @Test
    void consentIfConfiguredDisplayConsentTextWhenNoLinkConfigured() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
                randomZoneSubdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        zone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);
        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        MockMvcUtils.updateZone(mockMvc, zone);

        mockMvc.perform(get("/create_account")
                        .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost")))
                .andExpect(content().string(containsString(consentText)));
    }

    @Test
    void consentIfConfiguredDisplaysMeaningfulErrorWhenConsentNotProvided() throws Exception {
        String randomZoneSubdomain = generator.generate();
        String consentText = "Terms and Conditions";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(
                randomZoneSubdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        zone.getConfig().setBranding(new BrandingInformation());
        zone.getConfig().getBranding().setConsent(new Consent());
        zone.getConfig().getBranding().getConsent().setText(consentText);
        MockMvcUtils.updateZone(mockMvc, zone);

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(new SetServerNameRequestPostProcessor(randomZoneSubdomain + ".localhost"))
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", USER_PASSWORD)
                        .param("password_confirmation", USER_PASSWORD)
                        .param("does_user_consent", "false"))
                .andExpect(content().string(containsString("Please agree before continuing.")));
    }

    private UaaClientDetails createTestClient() throws Exception {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("test-client-" + RandomStringUtils.randomAlphanumeric(200));
        clientDetails.setClientSecret("test-client-secret");
        clientDetails.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
        clientDetails.setRegisteredRedirectUri(Collections.singleton("http://redirect.uri/*"));
        clientDetails.addAdditionalInformation(EmailAccountCreationService.SIGNUP_REDIRECT_URL, "http://redirect.uri/fallback");

        UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(), "clients.admin");
        return MockMvcUtils.createClient(mockMvc, adminToken, clientDetails);
    }

    private void createAccount(String expectedRedirectUri, String redirectUri) throws Exception {
        setPredictableGenerator();
        UaaClientDetails clientDetails = createTestClient();

        MockHttpSession session = getCreateAccountForm();

        mockMvc.perform(post("/create_account.do")
                        .with(csrf(session))
                        .param("email", userEmail)
                        .param("password", USER_PASSWORD)
                        .param("password_confirmation", USER_PASSWORD)
                        .param("client_id", clientDetails.getClientId())
                        .param("redirect_uri", redirectUri))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("accounts/email_sent"));

        FakeJavaMailSender.MimeMessageWrapper message = fakeJavaMailSender.getSentMessages().getFirst();
        assertThat(message.getContentString()).contains(UAA_AUTHOR);
        assertThat(message.getMessage().getHeader("From")).contains(UAA_AUTHOR + " " + UAA_AUTHOR_ADDRESS);

        mockMvc.perform(get("/verify_user")
                        .param("code", "test" + PREDICTABLE_GENERATOR.counter.get()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_REDIRECT + "&form_redirect_uri=" + expectedRedirectUri))
                .andReturn();

        MvcResult mvcResult = loginWithAccount("")
                .andExpect(authenticated())
                .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo(userEmail);
        assertThat(principal.getOrigin()).isEqualTo(OriginKeys.UAA);
    }

    private void setPredictableGenerator() {
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(PREDICTABLE_GENERATOR);
    }

    private ResultActions loginWithAccount(String subdomain) throws Exception {

        MockHttpSession session = getCreateAccountForm();

        MockHttpServletRequestBuilder req = post("/login.do")
                .param("username", userEmail)
                .param("password", USER_PASSWORD)
                .with(csrf(session));

        if (hasText(subdomain)) {
            req.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }

        return mockMvc.perform(req)
                .andExpect(status().isFound());
    }

    private MockHttpSession getCreateAccountForm() {
        MockHttpSession session = new MockHttpSession();
        MockMvcUtils.getCreateAccountForm(mockMvc, session);
        return session;
    }

}
