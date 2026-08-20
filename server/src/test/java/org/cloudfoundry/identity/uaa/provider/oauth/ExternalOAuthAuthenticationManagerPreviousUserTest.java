package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Test class to verify that ExternalOAuthAuthenticationManager properly tracks
 * previousUser for SNS event publishing when user attributes change during OIDC authentication.
 */
@ExtendWith(MockitoExtension.class)
class ExternalOAuthAuthenticationManagerPreviousUserTest {

        @Mock
        private IdentityProviderProvisioning providerProvisioning;
        @Mock
        private IdentityZoneManager identityZoneManager;
        @Mock
        private UaaUserDatabase userDatabase;
        @Mock
        private RestTemplate trustingRestTemplate;
        @Mock
        private RestTemplate nonTrustingRestTemplate;
        @Mock
        private TokenEndpointBuilder tokenEndpointBuilder;
        @Mock
        private KeyInfoService keyInfoService;
        @Mock
        private OidcMetadataFetcher oidcMetadataFetcher;
        @Mock
        private ApplicationEventPublisher eventPublisher;
    
    private ExternalOAuthCodeToken mockAuthentication;

    private ExternalOAuthAuthenticationManager authManager;
    private IdentityProvider<OIDCIdentityProviderDefinition> provider;
    private OIDCIdentityProviderDefinition config;
    private String origin = "oidc-provider";
    private String zoneId = "test-zone";

    @BeforeEach
    void setUp() {
        // Set up identity zone
        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        IdentityZoneHolder.set(zone);

        // Create mock authentication token
        mockAuthentication = mock(ExternalOAuthCodeToken.class);

        // Create authentication manager
        authManager = new ExternalOAuthAuthenticationManager(
                providerProvisioning,
                identityZoneManager,
                trustingRestTemplate,
                nonTrustingRestTemplate,
                tokenEndpointBuilder,
                keyInfoService,
                oidcMetadataFetcher
        );
        authManager.setUserDatabase(userDatabase);
        authManager.setApplicationEventPublisher(eventPublisher);
        authManager.setOrigin(origin);

        // Set up OIDC provider configuration
        config = new OIDCIdentityProviderDefinition();
        config.setAddShadowUserOnLogin(true);
        
        provider = new IdentityProvider<>();
        provider.setOriginKey(origin);
        provider.setType(OriginKeys.OIDC10);
        provider.setConfig(config);

        lenient().when(providerProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void testUserAuthenticated_whenAttributesChange_shouldAttachPreviousUser() {
        // Arrange - Create existing user from DB
        UaaUserPrototype existingPrototype = new UaaUserPrototype()
                .withId("user-123")
                .withUsername("john.doe")
                .withEmail("john@example.com")
                .withGivenName("John")
                .withFamilyName("Doe")
                .withPhoneNumber("+1234567890")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-123")
                .withLastLogonSuccess(1000L);

        UaaUser existingUser = new UaaUser(existingPrototype);

        // Arrange - Create updated user from OIDC request with changed attributes
        UaaUserPrototype updatedPrototype = new UaaUserPrototype()
                .withId("user-123")
                .withUsername("john.doe")
                .withEmail("john.newemail@example.com")  // Changed email
                .withGivenName("Jonathan")  // Changed given name
                .withFamilyName("Doe")
                .withPhoneNumber("+1234567890")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-123")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("user")));

        UaaUser updatedUserFromRequest = new UaaUser(updatedPrototype);

        // Mock the database retrieval to return updated user after modification
        UaaUserPrototype finalPrototype = existingPrototype
                .withEmail("john.newemail@example.com")
                .withGivenName("Jonathan");
        UaaUser finalUserFromDb = new UaaUser(finalPrototype);

        when(userDatabase.retrieveUserById("user-123")).thenReturn(finalUserFromDb);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertNotNull(result.getPreviousUser(), "PreviousUser should be attached to result");
        assertEquals(existingUser.getEmail(), result.getPreviousUser().getEmail(), 
                "PreviousUser should contain the old email");
        assertEquals("john@example.com", result.getPreviousUser().getEmail(),
                "PreviousUser should have original email");
        assertEquals("John", result.getPreviousUser().getGivenName(),
                "PreviousUser should have original given name");
        
        // Verify ExternalGroupAuthorizationEvent was published
        ArgumentCaptor<ExternalGroupAuthorizationEvent> eventCaptor = 
                ArgumentCaptor.forClass(ExternalGroupAuthorizationEvent.class);
        verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
        
        ExternalGroupAuthorizationEvent event = eventCaptor.getValue();
        assertTrue(event.isUserModified(), "Event should indicate user was modified");
    }

    @Test
    void testUserAuthenticated_whenNoAttributesChange_shouldNotAttachPreviousUser() {
        // Arrange - Create user with same attributes in DB and request
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withId("user-456")
                .withUsername("jane.smith")
                .withEmail("jane@example.com")
                .withGivenName("Jane")
                .withFamilyName("Smith")
                .withPhoneNumber("+9876543210")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-456")
                .withLastLogonSuccess(2000L);

        UaaUser existingUser = new UaaUser(prototype);
        UaaUser updatedUserFromRequest = new UaaUser(prototype.withAuthorities(
                Collections.singletonList(new SimpleGrantedAuthority("user"))));

        when(userDatabase.retrieveUserById("user-456")).thenReturn(existingUser);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertNull(result.getPreviousUser(), "PreviousUser should not be attached when no changes");
        
        // Verify ExternalGroupAuthorizationEvent was published
        ArgumentCaptor<ExternalGroupAuthorizationEvent> eventCaptor = 
                ArgumentCaptor.forClass(ExternalGroupAuthorizationEvent.class);
        verify(eventPublisher, times(1)).publishEvent(eventCaptor.capture());
        
        ExternalGroupAuthorizationEvent event = eventCaptor.getValue();
        assertFalse(event.isUserModified(), "Event should indicate user was not modified");
    }

    @Test
    void testUserAuthenticated_whenEmailChanges_shouldTrackChange() {
        // Arrange
        UaaUserPrototype existingPrototype = new UaaUserPrototype()
                .withId("user-789")
                .withUsername("test.user")
                .withEmail("old@example.com")
                .withGivenName("Test")
                .withFamilyName("User")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-789");

        UaaUser existingUser = new UaaUser(existingPrototype);

        UaaUserPrototype updatedPrototype = existingPrototype
                .withEmail("new@example.com")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("user")));

        UaaUser updatedUserFromRequest = new UaaUser(updatedPrototype);

        UaaUser finalUser = new UaaUser(existingPrototype.withEmail("new@example.com"));
        when(userDatabase.retrieveUserById("user-789")).thenReturn(finalUser);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result.getPreviousUser(), "PreviousUser should be attached");
        assertEquals("old@example.com", result.getPreviousUser().getEmail());
    }

    @Test
    void testUserAuthenticated_whenPhoneNumberChanges_shouldTrackChange() {
        // Arrange
        UaaUserPrototype existingPrototype = new UaaUserPrototype()
                .withId("user-101")
                .withUsername("phone.user")
                .withEmail("user@example.com")
                .withGivenName("Phone")
                .withFamilyName("User")
                .withPhoneNumber("+1111111111")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-101");

        UaaUser existingUser = new UaaUser(existingPrototype);

        UaaUserPrototype updatedPrototype = existingPrototype
                .withPhoneNumber("+2222222222")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("user")));

        UaaUser updatedUserFromRequest = new UaaUser(updatedPrototype);

        UaaUser finalUser = new UaaUser(existingPrototype.withPhoneNumber("+2222222222"));
        when(userDatabase.retrieveUserById("user-101")).thenReturn(finalUser);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result.getPreviousUser(), "PreviousUser should be attached");
        assertEquals("+1111111111", result.getPreviousUser().getPhoneNumber());
    }

    @Test
    void testUserAuthenticated_whenMultipleAttributesChange_shouldTrackAllChanges() {
        // Arrange
        UaaUserPrototype existingPrototype = new UaaUserPrototype()
                .withId("user-202")
                .withUsername("multi.user")
                .withEmail("multi@example.com")
                .withGivenName("Multi")
                .withFamilyName("User")
                .withPhoneNumber("+3333333333")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-202");

        UaaUser existingUser = new UaaUser(existingPrototype);

        // Change multiple attributes
        UaaUserPrototype updatedPrototype = existingPrototype
                .withEmail("newmulti@example.com")
                .withGivenName("NewMulti")
                .withFamilyName("NewUser")
                .withPhoneNumber("+4444444444")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("user")));

        UaaUser updatedUserFromRequest = new UaaUser(updatedPrototype);

        UaaUser finalUser = new UaaUser(updatedPrototype);
        when(userDatabase.retrieveUserById("user-202")).thenReturn(finalUser);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result.getPreviousUser(), "PreviousUser should be attached");
        assertEquals("multi@example.com", result.getPreviousUser().getEmail());
        assertEquals("Multi", result.getPreviousUser().getGivenName());
        assertEquals("User", result.getPreviousUser().getFamilyName());
        assertEquals("+3333333333", result.getPreviousUser().getPhoneNumber());
    }

    @Test
    void testUserAuthenticated_preservesPreviousUserThroughDatabaseRetrieval() {
        // This test ensures that previousUser survives the database retrieval step
        
        // Arrange
        UaaUserPrototype existingPrototype = new UaaUserPrototype()
                .withId("user-303")
                .withUsername("preserve.user")
                .withEmail("preserve@example.com")
                .withGivenName("Preserve")
                .withFamilyName("User")
                .withOrigin(origin)
                .withZoneId(zoneId)
                .withExternalId("external-303");

        UaaUser existingUser = new UaaUser(existingPrototype);

        UaaUserPrototype updatedPrototype = existingPrototype
                .withEmail("newpreserve@example.com")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("user")));

        UaaUser updatedUserFromRequest = new UaaUser(updatedPrototype);

        // Database returns user without previousUser
        UaaUser userFromDb = new UaaUser(existingPrototype.withEmail("newpreserve@example.com"));
        when(userDatabase.retrieveUserById("user-303")).thenReturn(userFromDb);

        // Act
        UaaUser result = authManager.userAuthenticated(mockAuthentication, updatedUserFromRequest, existingUser);

        // Assert
        assertNotNull(result.getPreviousUser(), 
                "PreviousUser should be preserved even after database retrieval");
        assertEquals("preserve@example.com", result.getPreviousUser().getEmail());
    }
}
