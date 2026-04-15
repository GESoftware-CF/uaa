package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthenticationSuccessListenerTests {

    private AuthenticationSuccessListener listener;
    private ScimUserProvisioning mockScimUserProvisioning;
    private UaaUserDatabase mockUaaUserDatabase;
    private UaaAuthentication mockUaaAuthentication;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private UserAttributeChangeEventPublisher mockUserAttributeChangeEventPublisher;
    private TimeService mockTimeService;
    private String id;
    private UaaUserPrototype userPrototype;
    private UaaUser user;

    @BeforeEach
    void setUp() {
        mockUaaAuthentication = mock(UaaAuthentication.class);
        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockUaaUserDatabase = mock(UaaUserDatabase.class);
        mockUserAttributeChangeEventPublisher = mock(UserAttributeChangeEventPublisher.class);
        mockTimeService = mock(TimeService.class);
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());
        listener = new AuthenticationSuccessListener(mockScimUserProvisioning, mockUaaUserDatabase, mockTimeService);
        listener.setApplicationEventPublisher(mockApplicationEventPublisher);
        listener.setUserAttributeChangeEventPublisher(mockUserAttributeChangeEventPublisher);
        id = "user-id";
        userPrototype = new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com");
        user = new UaaUser(userPrototype);
    }

    private ScimUser getScimUser(UaaUser user) {
        ScimUser scimUser = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scimUser.setVerified(user.isVerified());
        return scimUser;
    }

    @Test
    void unverifiedUserBecomesVerifiedIfTheyHaveLegacyFlag() {
        userPrototype
                .withVerified(false)
                .withLegacyVerificationBehavior(true);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning).verifyUser(eq(id), eq(-1), eq(zoneId));
    }

    @Test
    void unverifiedUserDoesNotBecomeVerifiedIfTheyHaveNoLegacyFlag() {
        userPrototype.withVerified(false);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning, never()).verifyUser(anyString(), anyInt(), eq(zoneId));
    }

    @Test
    void userLastUpdatedGetsCalledOnEvent() {
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();

        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning, times(1)).updateLastLogonTime(any(UaaUser.class), eq(zoneId));
    }

    @Test
    void previousLoginIsSetOnTheAuthentication() {
        userPrototype
                .withLastLogonSuccess(123456789L);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(this.id, zoneId)).thenReturn(getScimUser(event.getUser()));
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        listener.onApplicationEvent(event);
        verify(authentication).setLastLoginSuccessTime(123456789L);
    }

    @Test
    void provider_authentication_success_triggers_user_authentication_success() {
        IdentityProviderAuthenticationSuccessEvent event = new IdentityProviderAuthenticationSuccessEvent(
                user,
                mockUaaAuthentication,
                OriginKeys.UAA, IdentityZoneHolder.getCurrentZoneId()
        );
        listener.onApplicationEvent(event);
        verify(mockApplicationEventPublisher, times(1)).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

    @Test
    void userAttributeChangeEventPublisher_is_called_when_user_logs_in() {
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();

        UaaUser updatedUser = new UaaUser(userPrototype.withLastLogonSuccess(System.currentTimeMillis()));
        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        when(mockUaaUserDatabase.retrieveUserById(id)).thenReturn(updatedUser);

        listener.onApplicationEvent(event);

        verify(mockUserAttributeChangeEventPublisher, times(1))
                .publishUserAttributeChangeEventAsync(eq(listener), any(UaaUser.class));
    }

    @Test
    void userAttributeChangeEventPublisher_is_called_even_when_database_returns_null() {
        // This test verifies that publisher is called with the user from the event,
        // even if database retrieval returns null (database retrieval is not used)
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();

        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        when(mockUaaUserDatabase.retrieveUserById(id)).thenReturn(null);

        listener.onApplicationEvent(event);

        // Publisher should still be called because the user from the event is not null
        verify(mockUserAttributeChangeEventPublisher, times(1))
                .publishUserAttributeChangeEventAsync(any(), any(UaaUser.class));
    }

    private UserAuthenticationSuccessEvent getEvent() {
        user = new UaaUser(userPrototype);
        return new UserAuthenticationSuccessEvent(user, mockUaaAuthentication, IdentityZoneHolder.getCurrentZoneId());
    }

}
