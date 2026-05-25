package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class MergedZoneBrandingInformationTest {

    private BrandingInformation zoneBranding;
    private BrandingInformation defaultZoneBranding;
    private IdentityZone fakeUaa;

    @BeforeEach
    void setUp() {
        defaultZoneBranding = new BrandingInformation();
        final String productLogo = getResourceAsString(getClass(), "IdentityZoneHolderTest_ProductLogo");
        defaultZoneBranding.setProductLogo(productLogo);

        zoneBranding = new BrandingInformation();
        zoneBranding.setProductLogo("zoneBrandingString===");

        fakeUaa = IdentityZoneHolder.getUaaZone();
        fakeUaa.getConfig().setBranding(defaultZoneBranding);

        IdentityZoneProvisioning provisioning = Mockito.mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);

        Mockito.when(provisioning.retrieve(fakeUaa.getId())).thenReturn(fakeUaa);
    }

    @Test
    void getProductLogoForZone() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(zoneBranding);

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(zoneBranding.getProductLogo()).isEqualTo(brandingInformationSource.getProductLogo());
    }

    @Test
    void emptyProductLogoForZoneDoesNotReturnDefault() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        IdentityZoneHolder.get().getConfig().setBranding(new BrandingInformation());

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(brandingInformationSource.getProductLogo()).isNull();
    }

    @Test
    void getProductLogoForDefaultZoneReturnsDefaultLogo() {
        IdentityZoneHolder.set(fakeUaa);

        BrandingInformationSource brandingInformationSource = MergedZoneBrandingInformation.resolveBranding();
        assertThat(defaultZoneBranding.getProductLogo()).isEqualTo(brandingInformationSource.getProductLogo());
    }

    @Test
    void getBackgroundImageUrlReturnsZoneSpecificUrl() {
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);
        BrandingInformation branding = new BrandingInformation();
        branding.setBackgroundImageUrl("https://s3.example.com/zone/background-image?v=1");
        IdentityZoneHolder.get().getConfig().setBranding(branding);

        BrandingInformationSource source = MergedZoneBrandingInformation.resolveBranding();
        assertThat(source.getBackgroundImageUrl()).isEqualTo("https://s3.example.com/zone/background-image?v=1");
    }

    @Test
    void getBackgroundImageUrlFallsBackToUaaZoneUrl() {
        defaultZoneBranding.setBackgroundImageUrl("https://s3.example.com/default/background-image");
        fakeUaa.getConfig().setBranding(defaultZoneBranding);

        IdentityZone testZone = new IdentityZone();
        testZone.getConfig().setBranding(new BrandingInformation()); // no backgroundImageUrl
        IdentityZoneHolder.set(testZone);

        BrandingInformationSource source = MergedZoneBrandingInformation.resolveBranding();
        assertThat(source.getBackgroundImageUrl()).isEqualTo("https://s3.example.com/default/background-image");
    }

    @Test
    void getBackgroundImageUrlReturnsNullWhenNeitherZoneHasUrl() {
        IdentityZone testZone = new IdentityZone();
        testZone.getConfig().setBranding(new BrandingInformation());
        IdentityZoneHolder.set(testZone);
        // fakeUaa has no backgroundImageUrl set (only productLogo)

        BrandingInformationSource source = MergedZoneBrandingInformation.resolveBranding();
        assertThat(source.getBackgroundImageUrl()).isNull();
    }
}