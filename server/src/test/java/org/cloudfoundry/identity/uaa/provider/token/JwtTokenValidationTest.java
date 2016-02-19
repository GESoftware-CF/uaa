package org.cloudfoundry.identity.uaa.provider.token;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class JwtTokenValidationTest {

    private final static String TENANT_ID = "tenant_id";
    private final static String ISSUER_ID = "jb-machine-client";
    private final static String AUDIENCE =  "https://zone1.uaa.ge.com/oauth/token";
    
    @InjectMocks
    private JWTBearerAssertionTokenValidator tokenValidator = new JWTBearerAssertionTokenValidator(AUDIENCE);

    @Mock
    private ClientDetailsService clientDetailsService;
    
    @Before
    public void beforeMethod() {
        MockitoAnnotations.initMocks(this);
        this.tokenValidator.setClientPublicKeyProvider(new MockPublicKeyProvider());
        when(clientDetailsService.loadClientByClientId(anyString()))
        .thenReturn(new BaseClientDetails(ISSUER_ID, null, null, null, null, null));
    }
    
    @Test
    public void testPerformAuthenticationSuccess() {
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        System.out.println("Token: " + token);
        this.tokenValidator.setClientDetailsService(this.clientDetailsService);
        Assert.assertTrue(tokenValidator.performClientAuthentication(token)!=null);
    }
    
    @Test
    public void testPerformAuthenticationFailed() {
        String token = new MockAssertionToken().mockAssertionToken("nonexistent-client", System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        System.out.println("Token: " + token);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(null);
        this.tokenValidator.setClientDetailsService(this.clientDetailsService);
        Assert.assertNull(tokenValidator.performClientAuthentication(token));
    }

    @Test
    public void testTokenValidateSuccess() {
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        System.out.println("Token: " + token);
        this.tokenValidator.setClientDetailsService(this.clientDetailsService);
        Assert.assertEquals(true, tokenValidator.validateToken(token));
    }

    @Test
    public void testInvalidSigningKey() {
        MockAssertionToken testTokenUtil = new MockAssertionToken(TestKeys.INCORRECT_TOKEN_SIGNING_KEY);
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        Assert.assertEquals(false, tokenValidator.validateToken(token));
    }

    @Test
    public void testMissingToken() {
        Assert.assertEquals(false, tokenValidator.validateToken(null));
    }

    @Test
    public void testExpiredToken() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                60, TENANT_ID, AUDIENCE);
        tokenValidator.setClientDetailsService(this.clientDetailsService);
        Assert.assertEquals(false, tokenValidator.validateToken(token));
    }

    @Test
    public void JwtTokenTestWrongAudience() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, "https://zone1.wrong-uaa.com");
        tokenValidator.setClientDetailsService(this.clientDetailsService);
        Assert.assertEquals(false, tokenValidator.validateToken(token));
    }

    @Test
    public void JwtTokenTestNonExistentClient() {
        ClientDetailsService nullClientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(null);
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken("nonexistent-client",
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE);
        tokenValidator.setClientDetailsService(nullClientDetailsService);
        Assert.assertEquals(false, tokenValidator.validateToken(token));
    }
}
