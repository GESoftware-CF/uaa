package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class S3BackgroundImageUrlProviderTest {

    private static final String DEFAULT_URL = "https://s3.example.com/default-background.jpg";
    private static final String ZONE_URL    = "https://s3.example.com/uaa/zone1/background-image?v=1700000000000";

    @BeforeEach
    void setUp() {
        IdentityZone zone = buildZone("zone1");
        IdentityZoneHolder.set(zone);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void shouldReturnZoneUrlWhenConfigured() {
        IdentityZoneHolder.get().getConfig().getBranding().setBackgroundImageUrl(ZONE_URL);
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(ZONE_URL);
    }

    @Test
    void shouldReturnDefaultUrlWhenZoneHasNoBackgroundImage() {
        // zone branding exists but backgroundImageUrl is null
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(DEFAULT_URL);
    }

    @Test
    void shouldReturnDefaultUrlWhenZoneUrlIsBlank() {
        IdentityZoneHolder.get().getConfig().getBranding().setBackgroundImageUrl("   ");
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(DEFAULT_URL);
    }

    @Test
    void shouldReturnEmptyWhenNoZoneUrlAndNoDefault() {
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider("");

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenDefaultUrlIsNull() {
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(null);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnDefaultUrlWhenZoneConfigIsNull() {
        IdentityZoneHolder.get().setConfig(null);
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(DEFAULT_URL);
    }

    @Test
    void shouldReturnDefaultUrlWhenZoneBrandingIsNull() {
        IdentityZoneHolder.get().getConfig().setBranding(null);
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(DEFAULT_URL);
    }

    @Test
    void zoneUrlTakesPrecedenceOverDefault() {
        IdentityZoneHolder.get().getConfig().getBranding().setBackgroundImageUrl(ZONE_URL);
        S3BackgroundImageUrlProvider provider = new S3BackgroundImageUrlProvider(DEFAULT_URL);

        Optional<String> result = provider.getBackgroundImageUrl();

        assertThat(result).contains(ZONE_URL).doesNotContain(DEFAULT_URL);
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static IdentityZone buildZone(String id) {
        IdentityZone zone = new IdentityZone();
        zone.setId(id);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(new BrandingInformation());
        zone.setConfig(config);
        return zone;
    }
}
