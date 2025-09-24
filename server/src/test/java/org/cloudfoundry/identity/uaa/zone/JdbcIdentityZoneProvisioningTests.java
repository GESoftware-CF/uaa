package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@WithDatabaseContext
class JdbcIdentityZoneProvisioningTests {

    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private RandomValueStringGenerator randomValueStringGenerator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcIdentityZoneProvisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        randomValueStringGenerator = new RandomValueStringGenerator(8);
        jdbcTemplate.execute("delete from orchestrator_zone where identity_zone_id != 'uaa'");
        jdbcTemplate.execute("delete from identity_zone where id != 'uaa'");
    }

    @Test
    void delete_zone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{createdIdZone.getId()})).isOne();
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{createdIdZone.getId()})).isZero();
    }

    @Test
    void cannot_delete_uaa_zone() {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId()})).isOne();
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", Integer.class, new Object[]{IdentityZone.getUaaZoneId()})).isOne();
    }

    @Test
    void createIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(3600);
        assertThat(createdIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(7200);
        assertThat(createdIdZone.isActive()).isTrue();

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(createdIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(createdIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testCreateIdentityZone_enabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(createdIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(createdIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void testCreateIdentityZone_enabledSelfServiceCreateAccount() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
    }

    @Test
    void testCreateIdentityZone_enabledSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(true);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertTrue(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
    }

    @Test
    void testCreateIdentityZone_disabledSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceResetPasswordEnabled(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
    }

    @Test
    void testCreateIdentityZone_bothEnabledSelfServiceCreateAccountAndSelfServiceResetPassword() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertTrue(createdIdZone.isActive());

        assertFalse(createdIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
    }

    @Test
    void createIdentityZoneSubdomainBecomesLowerCase() {
        String subdomain = randomValueStringGenerator.generate().toUpperCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subdomain);
        identityZone.setId(randomValueStringGenerator.generate());

        identityZone.setSubdomain(subdomain);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(subdomain.toLowerCase());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());
    }

    @Test
    void null_subdomain() {
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieveBySubdomain(null));
    }

    @Test
    void updateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain);
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.getId()).isEqualTo(createdIdZone.getId());
        assertThat(updatedIdZone.getSubdomain()).isEqualTo(createdIdZone.getSubdomain().toLowerCase());
        assertThat(updatedIdZone.getName()).isEqualTo(createdIdZone.getName());
        assertThat(updatedIdZone.getDescription()).isEqualTo(createdIdZone.getDescription());
        assertThat(updatedIdZone.isActive()).isEqualTo(createdIdZone.isActive());
    }

    @Test
    void updateIdentityZoneSubDomainIsLowerCase() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(createdIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(createdIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(createdIdZone.getDescription()).isEqualTo(identityZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain.toUpperCase());
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.getId()).isEqualTo(createdIdZone.getId());
        assertThat(updatedIdZone.getSubdomain()).isEqualTo(createdIdZone.getSubdomain().toLowerCase());
        assertThat(updatedIdZone.getName()).isEqualTo(createdIdZone.getName());
        assertThat(updatedIdZone.getDescription()).isEqualTo(createdIdZone.getDescription());
    }

    @Test
    void createIdentityZoneInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.isActive()).isFalse();
    }

    @Test
    void updateIdentityZoneSetInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertThat(createdIdZone.isActive()).isTrue();

        createdIdZone.setActive(false);
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertThat(updatedIdZone.isActive()).isFalse();
    }

    @Test
    void deleteInactiveIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        int deletedZones = jdbcIdentityZoneProvisioning.deleteByIdentityZone(createdIdZone.getId());

        assertThat(deletedZones).isOne();
    }

    @Test
    void updateNonExistentIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.update(identityZone));
    }

    @Test
    void createDuplicateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    void createDuplicateIdentityZoneSubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            identityZone.setId(new RandomValueStringGenerator().generate());
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    void getIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup(null);
        identityZone.getConfig().getLinks().getSelfService().setPasswd(null);
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isTrue();

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testGetIdentityZone_disabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        identityZone.getConfig().getLinks().getSelfService().setSignup(null);
        identityZone.getConfig().getLinks().getSelfService().setPasswd(null);
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd());
        assertNull(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup());
    }

    @Test
    void testGetIdentityZone_enabledLegacySelfService() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void testGetIdentityZone_enabledLegacySelfServiceAndLinks() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        identityZone.getConfig().getLinks().getSelfService().setSignup("/create_account");
        identityZone.getConfig().getLinks().getSelfService().setPasswd("/forgot_password");
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());

        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "/create_account");
    }


    @Test
    void testGetIdentityZone_enabledLegacySelfServiceFlagAndPasswdLink() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        config.getLinks().getSelfService().setSignup("");
        config.getLinks().getSelfService().setPasswd("/forgot_password");
        identityZone.setConfig(config);

        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());

        assertFalse(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        assertTrue(retrievedIdZone.getConfig().getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertEquals(retrievedIdZone.getConfig().getLinks().getSelfService().getSignup(), "");
    }

    @Test
    void getAllIdentityZones() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        List<IdentityZone> identityZones = jdbcIdentityZoneProvisioning.retrieveAll();

        assertThat(identityZones)
                .hasSize(2)
                .contains(identityZone);
    }

    @Test
    void getIdentityZoneBySubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveBySubdomain(identityZone.getSubdomain());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isTrue();
    }

    @Test
    void testGetOrchestratorZoneByName() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        jdbcIdentityZoneProvisioning.create(identityZone);
        jdbcIdentityZoneProvisioning.createOrchestratorZone(identityZone.getId(), identityZone.getName());

        OrchestratorZoneEntity orchestratorZoneEntity = jdbcIdentityZoneProvisioning.retrieveByName(identityZone.getName());

        assertEquals(identityZone.getId(), orchestratorZoneEntity.getIdentityZoneId());
        assertEquals(identityZone.getSubdomain(), orchestratorZoneEntity.getSubdomain());
        assertEquals(identityZone.getName(), orchestratorZoneEntity.getOrchestratorZoneName());
        assertNotNull(identityZone.getCreated());
        assertNotNull(identityZone.getLastModified());
        assertNotNull(orchestratorZoneEntity.getId());
        assertNotNull(orchestratorZoneEntity.getCreated());
        assertNotNull(orchestratorZoneEntity.getLastModified());
    }

    @Test
    void testGetOrchZoneByIdentityZoneId() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(),
                randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        jdbcIdentityZoneProvisioning.create(identityZone);
        jdbcIdentityZoneProvisioning.createOrchestratorZone(identityZone.getId(), identityZone.getName());
        OrchestratorZoneEntity orchIdentityZoneEntity = jdbcIdentityZoneProvisioning.retrieveOrchestratorZoneByIdentityZoneId(identityZone.getId());
        assertEquals(identityZone.getId(), orchIdentityZoneEntity.getIdentityZoneId());
        assertEquals(identityZone.getName(), orchIdentityZoneEntity.getOrchestratorZoneName());
    }

    @Test
    void testGetOrchIdentityZoneById_NotFound() {
        String identityZoneId = randomValueStringGenerator.generate();
        try {
            OrchestratorZoneEntity orchIdentityZoneEntity = jdbcIdentityZoneProvisioning.retrieveOrchestratorZoneByIdentityZoneId(identityZoneId);
            fail("Able to retrieve orchestrator zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertEquals("Zone[" + identityZoneId + "] not found.", e.getMessage());
        }
    }

    @Test
    void testGetOrchIdentityZoneById_ZonePresentButNotPorted() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(),
                randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            OrchestratorZoneEntity orchestratorZone = jdbcIdentityZoneProvisioning.retrieveOrchestratorZoneByIdentityZoneId(identityZone.getId());
            assertNotNull(orchestratorZone);
            assertEquals(identityZone.getId(),orchestratorZone.getIdentityZoneId());
            assertNull(orchestratorZone.getOrchestratorZoneName());
        } catch (ZoneDoesNotExistsException e) {
            assertEquals("Zone[" + identityZone.getId() + "] not found.", e.getMessage());
        }
    }

    @Test
    void testCreateDuplicateZoneName() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(),
                                                                     randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        jdbcIdentityZoneProvisioning.create(identityZone);
        jdbcIdentityZoneProvisioning.createOrchestratorZone(identityZone.getId(), identityZone.getName());
        try {
            String newId = UUID.randomUUID().toString();
            identityZone.setId(newId);
            identityZone.setSubdomain(UUID.randomUUID().toString());
            jdbcIdentityZoneProvisioning.create(identityZone);
            jdbcIdentityZoneProvisioning.createOrchestratorZone(newId, identityZone.getName());
        } catch (ZoneAlreadyExistsException e) {
            assertEquals(
                "The zone name Test-Identity-Zone is already taken. Please use a different zone name",
                e.getMessage());
        }
    }

    @Test
    void testGetInactiveOrchestratorZoneByName() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        identityZone.setActive(false);
        jdbcIdentityZoneProvisioning.create(identityZone);
        jdbcIdentityZoneProvisioning.createOrchestratorZone(identityZone.getId(), identityZone.getName());
        try {
            jdbcIdentityZoneProvisioning.retrieveByName(identityZone.getName());
            fail("Able to retrieve inactive zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertEquals("Zone[Test-Identity-Zone] not found.", e.getMessage());
        }
    }

    @Test
    void testDeleteOrchestratorZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        jdbcIdentityZoneProvisioning.createOrchestratorZone(identityZone.getId(), identityZone.getName());
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from orchestrator_zone where identity_zone_id = ? and orchestrator_zone_name=?", new Object[]{createdIdZone.getId(), createdIdZone.getName()}, Integer.class), is(1));
        jdbcIdentityZoneProvisioning.deleteOrchestratorZone(identityZone.getName());
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from orchestrator_zone where identity_zone_id = ? and orchestrator_zone_name=?", new Object[]{createdIdZone.getId(), createdIdZone.getName()}, Integer.class), is(0));
    }

    @Test
    void testGetIdentityZoneByName_NotFound() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setName("Test-Identity-Zone");
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            jdbcIdentityZoneProvisioning.retrieveByName("random string");
        } catch (ZoneDoesNotExistsException e) {
            assertEquals("Zone[random string] not found.", e.getMessage());
        }
    }

    @Test
    void getInactiveIdentityZoneFails() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        try {
            jdbcIdentityZoneProvisioning.retrieve(createdIdZone.getId());
            fail("Able to retrieve inactive zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertThat(e.getMessage()).contains(createdIdZone.getId());
        }
    }

    @Test
    void getInactiveIdentityZoneIgnoringActiveFlag() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(createdIdZone.getId());

        assertThat(retrievedIdZone.getId()).isEqualTo(identityZone.getId());
        assertThat(retrievedIdZone.getSubdomain()).isEqualTo(identityZone.getSubdomain());
        assertThat(retrievedIdZone.getName()).isEqualTo(identityZone.getName());
        assertThat(retrievedIdZone.getDescription()).isEqualTo(identityZone.getDescription());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertThat(retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity()).isEqualTo(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertThat(retrievedIdZone.isActive()).isFalse();
    }

    @Test
    void identityZoneRetrieveZoneIdNull() {
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieve(null));
        assertThatExceptionOfType(ZoneDoesNotExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(null));
    }

    @Test
    void identityZoneUpdateSubDomainSame() {
        String subDomain = randomValueStringGenerator.generate();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subDomain);
        identityZone.setConfig(null);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        IdentityZone createdIdZone2 = jdbcIdentityZoneProvisioning.create(identityZone2);

        assertThat(createdIdZone2.getSubdomain()).isNotEqualTo(createdIdZone.getSubdomain());
        createdIdZone2.setConfig(null);
        createdIdZone2.setSubdomain(subDomain);
        assertThatExceptionOfType(ZoneAlreadyExistsException.class).isThrownBy(() -> jdbcIdentityZoneProvisioning.update(createdIdZone2));
    }

    @Test
    void createIdentityZoneInvalidZoneConfigResetConfigIntialValues() {
        String zoneId = randomValueStringGenerator.generate();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(createdIdZone).isNotNull();
        assertThat(createdIdZone.getConfig()).isNotNull();
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(3600);
        // corrupt the config entry
        jdbcTemplate.update("update identity_zone set config=? where id=?", "invalid", identityZone.getId());
        // retrieve zone again
        createdIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());
        assertThat(createdIdZone).isNotNull();
        assertThat(createdIdZone.getConfig()).isNotNull();
        assertThat(createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity()).isEqualTo(-1);
    }
}
