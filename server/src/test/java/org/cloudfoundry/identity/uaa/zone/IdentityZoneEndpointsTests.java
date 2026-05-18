package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeyProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeyProviderValidator;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.junit.jupiter.api.Nested;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class IdentityZoneEndpointsTests {

    private IdentityZone identityZone;

    @Mock
    private IdentityZoneProvisioning mockIdentityZoneProvisioning;

    @Mock
    private ScimGroupProvisioning mockScimGroupProvisioning;

    @Mock
    private KeyProviderProvisioning keyProviderProvisioning;

    @Mock
    private KeyProviderValidator keyProviderValidator;


    @Mock
    private IdentityZoneValidator mockIdentityZoneValidator;

    @Mock
    private JdbcIdentityProviderProvisioning mockIdentityProviderProvisioning;

    @Mock
    private ApplicationEventPublisher mockApplicationEventPublisher;

    @InjectMocks
    private IdentityZoneEndpoints endpoints;

    @BeforeEach
    void setUp() {
        endpoints.setApplicationEventPublisher(mockApplicationEventPublisher);
    }

    @Test
    void create_zone() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneProvisioning.create(any())).then(invocation -> invocation.getArgument(0));
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        identityZone = createZone();
        endpoints.createIdentityZone(identityZone, mock(BindingResult.class));
        verify(mockIdentityZoneProvisioning, times(1)).create(same(identityZone));
    }

    @Test
    void groups_are_created() {
        identityZone = createZone();
        endpoints.createUserGroups(identityZone);
        ArgumentCaptor<ScimGroup> captor = ArgumentCaptor.forClass(ScimGroup.class);
        List<String> defaultGroups = identityZone.getConfig().getUserConfig().getDefaultGroups();
        verify(mockScimGroupProvisioning, times(defaultGroups.size())).createOrGet(captor.capture(), eq(identityZone.getId()));
        assertThat(captor.getAllValues()).hasSameSizeAs(defaultGroups);
        assertThat(defaultGroups).containsExactlyInAnyOrder(captor.getAllValues().stream().map(
                ScimGroup::getDisplayName
        ).toArray(String[]::new));
    }

    @Test
    void group_creation_called_on_create() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneProvisioning.create(any())).then(invocation -> invocation.getArgument(0));
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        spy.createIdentityZone(identityZone, mock(BindingResult.class));
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void group_creation_called_on_update() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(identityZone.getId())).thenReturn(identityZone);
        when(mockIdentityZoneProvisioning.update(same(identityZone))).thenReturn(identityZone);
        spy.updateIdentityZone(identityZone, identityZone.getId());
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void remove_keys_from_map() {
        identityZone = createZone();

        endpoints.removeKeys(identityZone);

        assertThat(identityZone.getConfig().getSamlConfig().getPrivateKey()).isNull();
        assertThat(identityZone.getConfig().getSamlConfig().getPrivateKeyPassword()).isNull();
        identityZone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertThat(value.getKey()).isNull();
            assertThat(value.getPassphrase()).isNull();
        });
    }

    @Test
    void restore_keys() {
        remove_keys_from_map();
        IdentityZone original = createZone();
        endpoints.restoreSecretProperties(original, identityZone);


        assertThat(identityZone.getConfig().getSamlConfig().getPrivateKey()).isNotNull();
        assertThat(identityZone.getConfig().getSamlConfig().getPrivateKeyPassword()).isNotNull();
        identityZone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertThat(value.getKey()).isNotNull();
            assertThat(value.getPassphrase()).isNotNull();
        });

    }

    @Test
    void extend_zone_allowed_groups_on_update() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        IdentityZoneEndpoints spy = Mockito.spy(endpoints);
        identityZone = createZone();
        identityZone.getConfig().getUserConfig().setAllowedGroups(List.of("sps.write", "sps.read", "idps.write", "idps.read"));
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(identityZone.getId())).thenReturn(identityZone);
        when(mockIdentityZoneProvisioning.update(same(identityZone))).thenReturn(identityZone);
        List<ScimGroup> existingScimGroups = Stream.of("sps.write", "sps.read")
                .map(e -> new ScimGroup(e, e, identityZone.getId()))
                .toList();
        when(mockScimGroupProvisioning.retrieveAll(identityZone.getId())).thenReturn(existingScimGroups);
        spy.updateIdentityZone(identityZone, identityZone.getId());
        verify(spy, times(1)).createUserGroups(same(identityZone));
    }

    @Test
    void reduce_zone_allowed_groups_on_update_should_fail() throws InvalidIdentityZoneDetailsException {
        when(mockIdentityZoneValidator.validate(any(), any())).then(invocation -> invocation.getArgument(0));

        identityZone = createZone();
        identityZone.getConfig().getUserConfig().setAllowedGroups(List.of("clients.admin", "clients.write", "clients.read", "clients.secret"));
        String id = identityZone.getId();
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(id)).thenReturn(identityZone);
        List<ScimGroup> existingScimGroups = Stream.of("sps.write", "sps.read", "idps.write", "idps.read",
                        "clients.admin", "clients.write", "clients.read", "clients.secret", "scim.write", "scim.read", "scim.create", "scim.userids",
                        "scim.zones", "groups.update", "password.write", "oauth.login", "uaa.admin")
                .map(e -> new ScimGroup(e, e, id))
                .toList();
        when(mockScimGroupProvisioning.retrieveAll(id)).thenReturn(existingScimGroups);
        assertThatThrownBy(() -> endpoints.updateIdentityZone(identityZone, id))
                .isInstanceOf(UaaException.class)
                .hasMessage("The identity zone user configuration contains not-allowed groups.");
    }

    @Test
    void deleteIdentityZone_ShouldReject_IfIdpWithAliasExists() {
        final IdentityZone idz = new IdentityZone();
        final String idzId = new AlphanumericRandomValueStringGenerator(5).generate();
        idz.setName(idzId);
        idz.setId(idzId);
        idz.setSubdomain(idzId);
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(idzId)).thenReturn(idz);

        // arrange IdP with alias exists in zone
        when(mockIdentityProviderProvisioning.idpWithAliasExistsInZone(idzId)).thenReturn(true);
        mockOrchestratorEntity();

        final ResponseEntity<IdentityZone> response = endpoints.deleteIdentityZone(idzId);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    private void mockOrchestratorEntity() {
        OrchestratorZoneEntity mockedOrchestratorEntity = mock(OrchestratorZoneEntity.class);
        mockedOrchestratorEntity.setOrchestratorZoneName("test");
        when(mockIdentityZoneProvisioning.retrieveOrchestratorZoneByIdentityZoneId(anyString())).thenReturn(mockedOrchestratorEntity);
    }

    @Test
    void deleteIdentityZone_ShouldEmitEntityDeletedEvent_WhenNoAliasIdpExists() {
        final IdentityZone idz = new IdentityZone();
        final String idzId = new AlphanumericRandomValueStringGenerator(5).generate();
        idz.setName(idzId);
        idz.setId(idzId);
        idz.setSubdomain(idzId);
        when(mockIdentityZoneProvisioning.retrieveIgnoreActiveFlag(idzId)).thenReturn(idz);

        // arrange no IdP with alias exists in zone
        when(mockIdentityProviderProvisioning.idpWithAliasExistsInZone(idzId)).thenReturn(false);
        mockOrchestratorEntity();
        final ResponseEntity<IdentityZone> response = endpoints.deleteIdentityZone(idzId);
        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        final ArgumentCaptor<EntityDeletedEvent<IdentityZone>> eventArgument = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(mockApplicationEventPublisher).publishEvent(eventArgument.capture());
        final var capturedEvent = eventArgument.getValue();
        assertThat(capturedEvent.getDeleted()).isEqualTo(idz);
    }

    @Nested
    class RestoreBrandingPropertiesTests {

        private static final String EXISTING_IMAGE_URL    = "https://s3.example.com/img?v=1";
        private static final String EXISTING_UPLOADED_AT  = "2024-01-01T00:00:00Z";
        private static final String EXISTING_UPLOADED_BY  = "admin";

        @Test
        void shouldPreserveBackgroundImageUrlWhenNewZoneOmitsIt() {
            IdentityZone existing = createZone();
            existing.getConfig().setBranding(brandingWithImage(
                    EXISTING_IMAGE_URL, EXISTING_UPLOADED_AT, EXISTING_UPLOADED_BY));

            IdentityZone incoming = createZone();
            incoming.getConfig().setBranding(new BrandingInformation());

            endpoints.restoreBrandingProperties(existing, incoming);

            assertThat(incoming.getConfig().getBranding().getBackgroundImageUrl())
                    .isEqualTo(EXISTING_IMAGE_URL);
            assertThat(incoming.getConfig().getBranding().getBackgroundImageUploadedAt())
                    .isEqualTo(EXISTING_UPLOADED_AT);
            assertThat(incoming.getConfig().getBranding().getBackgroundImageUploadedBy())
                    .isEqualTo(EXISTING_UPLOADED_BY);
        }

        @Test
        void shouldNotOverwriteBackgroundImageUrlWhenNewZoneProvidesOne() {
            IdentityZone existing = createZone();
            existing.getConfig().setBranding(brandingWithImage(
                    "https://s3.example.com/old?v=1", EXISTING_UPLOADED_AT, EXISTING_UPLOADED_BY));

            IdentityZone incoming = createZone();
            incoming.getConfig().setBranding(brandingWithImage(
                    "https://s3.example.com/new?v=2", "2024-06-01T00:00:00Z", "editor"));

            endpoints.restoreBrandingProperties(existing, incoming);

            assertThat(incoming.getConfig().getBranding().getBackgroundImageUrl())
                    .isEqualTo("https://s3.example.com/new?v=2");
        }

        @Test
        void shouldHandleNullNewZoneBrandingGracefully() {
            IdentityZone existing = createZone();
            existing.getConfig().setBranding(brandingWithImage(
                    EXISTING_IMAGE_URL, EXISTING_UPLOADED_AT, EXISTING_UPLOADED_BY));

            IdentityZone incoming = createZone();
            incoming.getConfig().setBranding(null);

            endpoints.restoreBrandingProperties(existing, incoming);
        }

        @Test
        void shouldHandleNullExistingZoneBrandingGracefully() {
            IdentityZone existing = createZone();
            existing.getConfig().setBranding(null);

            IdentityZone incoming = createZone();
            incoming.getConfig().setBranding(new BrandingInformation());

            // should not throw NPE and incoming branding should remain unchanged
            endpoints.restoreBrandingProperties(existing, incoming);

            assertThat(incoming.getConfig().getBranding().getBackgroundImageUrl()).isNull();
        }

        @Test
        void shouldHandleNullConfigOnBothZonesGracefully() {
            IdentityZone existing = createZone();
            existing.setConfig(null);

            IdentityZone incoming = createZone();
            incoming.setConfig(null);

            // should not throw NPE
            endpoints.restoreBrandingProperties(existing, incoming);
        }

        @Test
        void shouldPreserveAllThreeFieldsTogetherAsAtomicUnit() {
            IdentityZone existing = createZone();
            existing.getConfig().setBranding(brandingWithImage(
                    "https://s3.example.com/img?v=99", "2025-01-15T10:30:00Z", "zone-admin"));

            IdentityZone incoming = createZone();
            incoming.getConfig().setBranding(new BrandingInformation());

            endpoints.restoreBrandingProperties(existing, incoming);

            BrandingInformation branding = incoming.getConfig().getBranding();
            assertThat(branding.getBackgroundImageUrl()).isEqualTo("https://s3.example.com/img?v=99");
            assertThat(branding.getBackgroundImageUploadedAt()).isEqualTo("2025-01-15T10:30:00Z");
            assertThat(branding.getBackgroundImageUploadedBy()).isEqualTo("zone-admin");
        }

        private static BrandingInformation brandingWithImage(String url, String uploadedAt, String uploadedBy) {
            BrandingInformation b = new BrandingInformation();
            b.setBackgroundImageUrl(url);
            b.setBackgroundImageUploadedAt(uploadedAt);
            b.setBackgroundImageUploadedBy(uploadedBy);
            return b;
        }
    }

    private static IdentityZone createZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        IdentityZoneConfiguration config = zone.getConfig();
        assertThat(config).isNotNull();
        zone.getConfig().getSamlConfig().setPrivateKey("private");
        zone.getConfig().getSamlConfig().setPrivateKeyPassword("passphrase");
        zone.getConfig().getSamlConfig().setCertificate("certificate");
        zone.getConfig().getSamlConfig().addAndActivateKey("active", new SamlKey("private1", "passphrase1", "certificate1"));

        assertThat(zone.getConfig().getSamlConfig().getPrivateKey()).isNotNull();
        assertThat(zone.getConfig().getSamlConfig().getPrivateKeyPassword()).isNotNull();
        zone.getConfig().getSamlConfig().getKeys().forEach((key, value) -> {
            assertThat(value.getKey()).isNotNull();
            assertThat(value.getPassphrase()).isNotNull();
        });
        return zone;
    }
}
