package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.account.UaaUserDetails;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class UaaClientAuthenticationProviderTest {

    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private MultitenantJdbcClientDetailsService jdbcClientDetailsService;
    private ClientDetails client;
    private ClientDetailsAuthenticationProvider authenticationProvider;
    private JwtClientAuthentication jwtClientAuthentication;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUpForClientTests() {
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        jwtClientAuthentication = mock(JwtClientAuthentication.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        jdbcClientDetailsService = new MultitenantJdbcClientDetailsService(namedJdbcTemplate, mockIdentityZoneManager, passwordEncoder);
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        client = createClient();
        authenticationProvider = new ClientDetailsAuthenticationProvider(clientDetailsService, passwordEncoder, jwtClientAuthentication);
    }

    public UaaClientDetails createClient() {
        return createClient(null, null);
    }

    public UaaClientDetails createClient(String addtionalKey, Object value) {
        UaaClientDetails details = new UaaClientDetails(generator.generate(), "", "", "client_credentials", "uaa.resource");
        details.setClientSecret(SECRET);
        if (addtionalKey != null) {
            details.addAdditionalInformation(addtionalKey, value);
        }
        jdbcClientDetailsService.addClientDetails(details);
        return details;
    }

    private UsernamePasswordAuthenticationToken getToken(String clientId, String clientSecret) {
        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }

    private void testClientAuthentication(Authentication a) {
        Authentication authentication = authenticationProvider.authenticate(a);
        assertThat(authentication).isNotNull();
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken(String grant_type) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("code_verifier", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        request.addParameter("code", "1234567890");
        request.addParameter("client_id", "id");
        request.addParameter("redirect_uri", "http://localhost:8080/uaa");
        request.addParameter("grant_type", grant_type);
        return getAuthenticationToken(request);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationTokenClientJwt(String grantType) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("code_verifier", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        request.addParameter("code", "1234567890");
        request.addParameter("client_assertion", "id");
        request.addParameter("client_assertion_type", "id");
        request.addParameter("redirect_uri", "http://localhost:8080/uaa");
        request.addParameter("grant_type", grantType);
        return getAuthenticationToken(request);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken(HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = new UaaAuthenticationDetails(request);
        when(authentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        return authentication;
    }

    @Test
    void provider_authenticate_client_with_one_password() {
        Authentication a = getToken(client.getClientId(), SECRET);
        testClientAuthentication(a);
    }

    @Test
    void provider_authenticate_client_without_password_public_string() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, "true");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_authenticate_client_with_empty_password_public_string() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
        UaaClientDetails clientDetails = new UaaClientDetails(generator.generate(), "", "", "password", "uaa.resource");
        clientDetails.setClientSecret("");
        jdbcClientDetailsService.addClientDetails(clientDetails);
        client = clientDetails;
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("password");
        when(a.getCredentials()).thenReturn("");
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("cf", passwordEncoder.encode(""), Collections.emptyList(), client.getAdditionalInformation(), null), a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_refresh_client_without_password_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token", "1234567890");
        request.addParameter("grant_type", "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_refresh_client_with_password_inAuthorizationHeader_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addHeader("Authorization", "client:secret");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token", "1234567890");
        request.addParameter("grant_type", "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void provider_refresh_client_without_wrong_endpoint() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.addParameter("client_id", "id");
        request.addParameter("refresh_token", "1234567890");
        request.addParameter("grant_type", "refresh_token");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void provider_authenticate_client_without_password_public_boolean() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_authenticate_client_without_password_public_wrong_grant_type() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("client_credentials");
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret secret2", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void provider_authenticate_no_details() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        UserDetails userDetails = new UaaUserDetails(new UaaUser("client", "secret", "mail@user", "", ""));
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(userDetails, a));
    }

    @Test
    void provider_authenticate_no_authenticationDetails() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = getAuthenticationToken("authorization_code");
        when(a.getDetails()).thenReturn(null);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret secret2", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void provider_authenticate_client_without_password_public_missing_code() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, true);
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = new HashMap<>();
        when(uaaAuthenticationDetails.getParameterMap()).thenReturn(requestParameters);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void provider_authenticate_client_without_secret_user_without_secret() {
        client = new UaaClientDetails(generator.generate(), "", "", "client_credentials", "uaa.resource");
        jdbcClientDetailsService.addClientDetails(client);
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = new HashMap<>();
        when(uaaAuthenticationDetails.getParameterMap()).thenReturn(requestParameters);
        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), client.getAdditionalInformation(), null);
        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }

    @Test
    void provider_authenticate_client_without_password_public_false() {
        client = createClient(ClientConstants.ALLOW_PUBLIC, false);
        UsernamePasswordAuthenticationToken a = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(a.getDetails()).thenReturn(uaaAuthenticationDetails);
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> testClientAuthentication(a));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_1() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        testClientAuthentication(getToken(client.getClientId(), SECRET));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_2() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        testClientAuthentication(getToken(client.getClientId(), "secret2"));
    }

    @Test
    void provider_authenticate_client_with_two_passwords_test_3() {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2", IdentityZoneHolder.get().getId());
        assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> testClientAuthentication(getToken(client.getClientId(), "secret3")));
    }

    @Test
    void clientJwt_authenticate_client_without_config() {
        UsernamePasswordAuthenticationToken a = getAuthenticationTokenClientJwt("authorization_code");
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(
                new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a));
    }

    @Test
    void clientJwt_authenticate_client_valid() {
        when(jwtClientAuthentication.validateClientJwt(any(), any(), any())).thenReturn(true);
        UsernamePasswordAuthenticationToken a = getAuthenticationTokenClientJwt("authorization_code");
        authenticationProvider.additionalAuthenticationChecks(
                new UaaClient("client", "secret", Collections.emptyList(), client.getAdditionalInformation(), null), a);
        assertThat(a).isNotNull();
    }


    // --- Tests for parseZoneClientIdMapping utility ---

    @Test
    void parseZoneClientIdMapping_null_returns_empty() {
        assertThat(ClientDetailsAuthenticationProvider.parseZoneClientIdMapping(null)).isEmpty();
    }

    @Test
    void parseZoneClientIdMapping_blank_returns_empty() {
        assertThat(ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("  ")).isEmpty();
    }

    @Test
    void parseZoneClientIdMapping_empty_string_returns_empty() {
        assertThat(ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("")).isEmpty();
    }

    @Test
    void parseZoneClientIdMapping_single_zone_single_client() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client1");
        assertThat(mapping)
                .hasSize(1)
                .containsEntry("zone1", Set.of("client1"));
    }

    @Test
    void parseZoneClientIdMapping_single_zone_multiple_clients() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client1,zone1:client2");
        assertThat(mapping)
                .hasSize(1)
                .containsEntry("zone1", Set.of("client1", "client2"));
    }

    @Test
    void parseZoneClientIdMapping_multiple_zones_multiple_clients() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client1,zone1:client2,zone2:client3,zone2:client4");
        assertThat(mapping)
                .hasSize(2)
                .containsEntry("zone1", Set.of("client1", "client2"))
                .containsEntry("zone2", Set.of("client3", "client4"));
    }

    @Test
    void parseZoneClientIdMapping_with_whitespace() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1 : client1 , zone2 : client2");
        assertThat(mapping)
                .hasSize(2)
                .containsEntry("zone1", Set.of("client1"))
                .containsEntry("zone2", Set.of("client2"));
    }

    @Test
    void parseZoneClientIdMapping_ignores_invalid_entries_without_colon() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client1,invalid_entry,zone2:client2");
        assertThat(mapping)
                .hasSize(2)
                .containsEntry("zone1", Set.of("client1"))
                .containsEntry("zone2", Set.of("client2"));
    }

    @Test
    void parseZoneClientIdMapping_ignores_entries_with_empty_parts() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client1,:client2,zone2:,zone2:client3");
        assertThat(mapping)
                .hasSize(2)
                .containsEntry("zone1", Set.of("client1"))
                .containsEntry("zone2", Set.of("client3"));
    }

    @Test
    void parseZoneClientIdMapping_handles_client_id_with_colon() {
        Map<String, Set<String>> mapping = ClientDetailsAuthenticationProvider.parseZoneClientIdMapping("zone1:client:special");
        assertThat(mapping)
                .hasSize(1)
                .containsEntry("zone1", Set.of("client:special"));
    }

    // --- Tests for zone-restricted legacy no-secret password grant ---

    @Test
    void provider_password_grant_without_secret_allowed_for_whitelisted_zone_and_client() {
        // Create provider with current zone and client whitelisted
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        Map<String, Set<String>> zoneClientMapping = Map.of(currentZoneId, Set.of("testclient"));
        ClientDetailsAuthenticationProvider whitelistedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "testclient");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        // Client with no password - should be allowed for whitelisted zone:client pair
        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        whitelistedProvider.additionalAuthenticationChecks(uaaClient, a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_password_grant_without_secret_rejected_for_non_whitelisted_zone_or_client() {
        // Create provider with a different zone/client pair whitelisted
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        Map<String, Set<String>> zoneClientMapping = Map.of("some-other-zone-id", Set.of("some-client"));
        ClientDetailsAuthenticationProvider restrictedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "testclient");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        assertThatThrownBy(() -> restrictedProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }

    @Test
    void provider_password_grant_without_secret_rejected_when_no_zones_whitelisted() {
        // Default provider has empty whitelist (no zones allowed)
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "testclient");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        assertThatThrownBy(() -> authenticationProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }

    @Test
    void provider_client_credentials_without_secret_rejected_even_for_whitelisted_zone() {
        // Legacy no-secret flow should only work for password grant, not client_credentials
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        // Whitelist multiple clients for this zone
        Map<String, Set<String>> zoneClientMapping = Map.of(currentZoneId, Set.of("testclient"));
        ClientDetailsAuthenticationProvider whitelistedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "testclient");
        request.addParameter("grant_type", "client_credentials");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        assertThatThrownBy(() -> whitelistedProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }

    // --- Tests for zone+client ID restricted legacy no-secret password grant ---

    @Test
    void provider_password_grant_allowed_for_whitelisted_zone_and_client() {
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        Map<String, Set<String>> zoneClientMapping = Map.of(currentZoneId, Set.of("testclient"));
        ClientDetailsAuthenticationProvider whitelistedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "testclient");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        whitelistedProvider.additionalAuthenticationChecks(uaaClient, a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_password_grant_rejected_for_whitelisted_zone_but_non_whitelisted_client() {
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        Map<String, Set<String>> zoneClientMapping = Map.of(currentZoneId, Set.of("allowed-client"));
        ClientDetailsAuthenticationProvider restrictedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "unauthorized-client");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        assertThatThrownBy(() -> restrictedProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }

    @Test
    void provider_password_grant_allowed_for_specific_client_in_whitelisted_zone() {
        // Test allowing specific whitelisted client in a zone by whitelisting multiple clients or a wildcard approach
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        // Whitelist multiple clients including the test client
        Map<String, Set<String>> zoneClientMapping = Map.of(currentZoneId, Set.of("any-client", "testclient", "legacy-app"));
        ClientDetailsAuthenticationProvider whitelistedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "any-client");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        whitelistedProvider.additionalAuthenticationChecks(uaaClient, a);
        assertThat(a).isNotNull();
    }

    @Test
    void provider_password_grant_with_multiple_clients_per_zone() {
        String currentZoneId = IdentityZoneHolder.getCurrentZoneId();
        UaaClientDetailsUserDetailsService clientDetailsService = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        Map<String, Set<String>> zoneClientMapping = Map.of(
                currentZoneId, Set.of("client1", "client2", "client3")
        );
        ClientDetailsAuthenticationProvider whitelistedProvider = new ClientDetailsAuthenticationProvider(
                clientDetailsService, passwordEncoder, jwtClientAuthentication,
                zoneClientMapping);

        for (String clientId : List.of("client1", "client2", "client3")) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
            request.addParameter("client_id", clientId);
            request.addParameter("grant_type", "password");
            UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

            UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
            whitelistedProvider.additionalAuthenticationChecks(uaaClient, a);
            assertThat(a).isNotNull();
        }

        // Test unauthorized client
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");
        request.addParameter("client_id", "unauthorized-client");
        request.addParameter("grant_type", "password");
        UsernamePasswordAuthenticationToken a = getAuthenticationToken(request);

        UaaClient uaaClient = new UaaClient("client", null, Collections.emptyList(), Collections.emptyMap(), null);
        assertThatThrownBy(() -> whitelistedProvider.additionalAuthenticationChecks(uaaClient, a))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing credentials");
    }
}
