package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BackgroundImageServiceTest {

    private static final String BUCKET    = "test-bucket";
    private static final String ZONE_ID   = "test-zone";
    private static final String S3_KEY    = "uaa/test-zone/background-image";
    private static final String BASE_URL  = "https://test-bucket.s3.us-east-1.amazonaws.com/" + S3_KEY;
    private static final String PNG_TYPE  = "image/png";
    private static final String PNG_FILE  = "img.png";
    private static final byte[] IMG_BYTES = "bytes".getBytes();

    @Mock private S3StorageManager s3StorageManager;
    @Mock private IdentityZoneProvisioning zoneProvisioning;

    private BackgroundImageService service;

    @BeforeEach
    void setUp() {
        service = new BackgroundImageService(s3StorageManager, zoneProvisioning, BUCKET);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // -------------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------------

    @Nested
    class UploadBackgroundImage {

        @Test
        void shouldUploadPngToS3AndPersistUrlInZoneConfig() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(BUCKET, S3_KEY)).thenReturn(BASE_URL);

            service.uploadBackgroundImage(file, ZONE_ID);

            verify(s3StorageManager).upload(eq(BUCKET), eq(S3_KEY), any(), eq((long) IMG_BYTES.length), eq(PNG_TYPE));

            ArgumentCaptor<IdentityZone> zoneCaptor = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(zoneCaptor.capture());
            BrandingInformation branding = zoneCaptor.getValue().getConfig().getBranding();
            assertThat(branding.getBackgroundImageUrl()).startsWith(BASE_URL + "?v=");
            assertThat(branding.getBackgroundImageUploadedAt()).isNotNull();
        }

        @ParameterizedTest
        @ValueSource(strings = {"image/jpeg", "image/webp"})
        void shouldAcceptJpegAndWebp(String mimeType) throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", "img", mimeType, IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);

            service.uploadBackgroundImage(file, ZONE_ID);

            verify(s3StorageManager).upload(eq(BUCKET), eq(S3_KEY), any(), anyLong(), eq(mimeType));
        }

        @ParameterizedTest
        @ValueSource(strings = {"image/gif", "image/tiff", "application/pdf", "application/octet-stream", "text/html"})
        void shouldReject415ForDisallowedMimeType(String mimeType) {
            MockMultipartFile file = new MockMultipartFile("file", "img", mimeType, IMG_BYTES);

            assertThatThrownBy(() -> service.uploadBackgroundImage(file, ZONE_ID))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE));

            verifyNoInteractions(s3StorageManager, zoneProvisioning);
        }

        @Test
        void shouldReject415ForNullContentType() {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, null, IMG_BYTES);

            assertThatThrownBy(() -> service.uploadBackgroundImage(file, ZONE_ID))
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(ex -> assertThat(((ResponseStatusException) ex).getStatusCode())
                            .isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE));

            verifyNoInteractions(s3StorageManager, zoneProvisioning);
        }

        @Test
        void shouldStripCharsetSuffixBeforeValidation() throws Exception {
            // "image/jpeg; charset=utf-8" should be treated as "image/jpeg"
            MockMultipartFile file = new MockMultipartFile("file", "img.jpg", "image/jpeg; charset=utf-8", IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);

            service.uploadBackgroundImage(file, ZONE_ID);

            verify(s3StorageManager).upload(eq(BUCKET), eq(S3_KEY), any(), anyLong(), eq("image/jpeg"));
        }

        @Test
        void shouldCreateConfigAndBrandingWhenZoneHasNone() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            IdentityZone zone = new IdentityZone();
            zone.setId(ZONE_ID);
            zone.setConfig(null);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);

            service.uploadBackgroundImage(file, ZONE_ID);

            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            assertThat(cap.getValue().getConfig()).isNotNull();
            assertThat(cap.getValue().getConfig().getBranding()).isNotNull();
            assertThat(cap.getValue().getConfig().getBranding().getBackgroundImageUrl()).isNotNull();
        }

        @Test
        void shouldPreserveOtherBrandingFieldsOnUpload() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            IdentityZone zone = buildZone(ZONE_ID);
            zone.getConfig().getBranding().setCompanyName("Acme Corp");
            zone.getConfig().getBranding().setProductLogo("logo-base64-data");
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);

            service.uploadBackgroundImage(file, ZONE_ID);

            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            assertThat(cap.getValue().getConfig().getBranding().getCompanyName()).isEqualTo("Acme Corp");
            assertThat(cap.getValue().getConfig().getBranding().getProductLogo()).isEqualTo("logo-base64-data");
        }

        @Test
        void shouldSetUploaderFromSecurityContext() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("zone-admin", "n/a"));

            service.uploadBackgroundImage(file, ZONE_ID);

            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            assertThat(cap.getValue().getConfig().getBranding().getBackgroundImageUploadedBy()).isEqualTo("zone-admin");
        }

        @Test
        void shouldSetUploaderToUnknownWhenNoSecurityContext() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(any(), any())).thenReturn(BASE_URL);
            SecurityContextHolder.clearContext();

            service.uploadBackgroundImage(file, ZONE_ID);

            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            assertThat(cap.getValue().getConfig().getBranding().getBackgroundImageUploadedBy()).isEqualTo("unknown");
        }

        @Test
        void shouldIncludeCacheBusterVersionInUrl() throws Exception {
            MockMultipartFile file = new MockMultipartFile("file", PNG_FILE, PNG_TYPE, IMG_BYTES);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(buildZone(ZONE_ID));
            when(s3StorageManager.getDirectUrl(BUCKET, S3_KEY)).thenReturn(BASE_URL);

            long before = System.currentTimeMillis();
            service.uploadBackgroundImage(file, ZONE_ID);
            long after = System.currentTimeMillis();

            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            String url = cap.getValue().getConfig().getBranding().getBackgroundImageUrl();
            long version = Long.parseLong(url.substring(url.indexOf("?v=") + 3));
            assertThat(version).isBetween(before, after);
        }
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    @Nested
    class DeleteBackgroundImage {

        @Test
        void shouldDeleteFromS3AndClearZoneMetadata() {
            IdentityZone zone = buildZoneWithImage(ZONE_ID, BASE_URL + "?v=123");
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);

            boolean result = service.deleteBackgroundImage(ZONE_ID);

            assertThat(result).isTrue();
            verify(s3StorageManager).delete(BUCKET, S3_KEY);
            ArgumentCaptor<IdentityZone> cap = ArgumentCaptor.forClass(IdentityZone.class);
            verify(zoneProvisioning).update(cap.capture());
            BrandingInformation branding = cap.getValue().getConfig().getBranding();
            assertThat(branding.getBackgroundImageUrl()).isNull();
            assertThat(branding.getBackgroundImageUploadedAt()).isNull();
            assertThat(branding.getBackgroundImageUploadedBy()).isNull();
        }

        @Test
        void shouldReturnFalseAndSkipS3WhenNoBrandingUrl() {
            IdentityZone zone = buildZone(ZONE_ID);
            // branding exists but backgroundImageUrl is null
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);

            boolean result = service.deleteBackgroundImage(ZONE_ID);

            assertThat(result).isFalse();
            verifyNoInteractions(s3StorageManager);
            verify(zoneProvisioning, never()).update(any());
        }

        @Test
        void shouldReturnFalseWhenZoneConfigIsNull() {
            IdentityZone zone = new IdentityZone();
            zone.setId(ZONE_ID);
            zone.setConfig(null);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);

            boolean result = service.deleteBackgroundImage(ZONE_ID);

            assertThat(result).isFalse();
            verifyNoInteractions(s3StorageManager);
        }

        @Test
        void shouldReturnFalseWhenZoneBrandingIsNull() {
            IdentityZone zone = new IdentityZone();
            zone.setId(ZONE_ID);
            IdentityZoneConfiguration config = new IdentityZoneConfiguration();
            config.setBranding(null);
            zone.setConfig(config);
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);

            boolean result = service.deleteBackgroundImage(ZONE_ID);

            assertThat(result).isFalse();
            verifyNoInteractions(s3StorageManager);
        }

        @Test
        void shouldPropagateS3ExceptionAndNotUpdateDatabase() {
            // If S3 delete fails, zone metadata must be preserved so the operator can retry
            IdentityZone zone = buildZoneWithImage(ZONE_ID, BASE_URL + "?v=123");
            when(zoneProvisioning.retrieve(ZONE_ID)).thenReturn(zone);
            doThrow(new RuntimeException("S3 connection refused")).when(s3StorageManager).delete(anyString(), anyString());

            assertThatThrownBy(() -> service.deleteBackgroundImage(ZONE_ID))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("S3 connection refused");

            // DB must NOT be updated — metadata survives for operator retry
            verify(zoneProvisioning, never()).update(any());
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static IdentityZone buildZone(String zoneId) {
        IdentityZone zone = new IdentityZone();
        zone.setId(zoneId);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        BrandingInformation branding = new BrandingInformation();
        config.setBranding(branding);
        zone.setConfig(config);
        return zone;
    }

    private static IdentityZone buildZoneWithImage(String zoneId, String imageUrl) {
        IdentityZone zone = buildZone(zoneId);
        zone.getConfig().getBranding().setBackgroundImageUrl(imageUrl);
        zone.getConfig().getBranding().setBackgroundImageUploadedAt("2024-01-01T00:00:00Z");
        zone.getConfig().getBranding().setBackgroundImageUploadedBy("admin");
        return zone;
    }

    // -------------------------------------------------------------------------
    // BackgroundImageUrlProvider — getBackgroundImageUrl()
    // -------------------------------------------------------------------------

    @Nested
    class GetBackgroundImageUrl {

        @BeforeEach
        void setUpZoneHolder() {
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.set(buildZoneWithImage(ZONE_ID, BASE_URL + "?v=1"));
        }

        @AfterEach
        void clearZoneHolder() {
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.clear();
        }

        @Test
        void shouldReturnUrlFromCurrentZoneBranding() {
            java.util.Optional<String> result = service.getBackgroundImageUrl();
            assertThat(result).isPresent().hasValue(BASE_URL + "?v=1");
        }

        @Test
        void shouldReturnEmptyWhenZoneHasNoBackgroundImageUrl() {
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.set(buildZone(ZONE_ID));
            java.util.Optional<String> result = service.getBackgroundImageUrl();
            assertThat(result).isEmpty();
        }

        @Test
        void shouldReturnEmptyWhenBrandingUrlIsBlank() {
            IdentityZone zone = buildZone(ZONE_ID);
            zone.getConfig().getBranding().setBackgroundImageUrl("   ");
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.set(zone);
            java.util.Optional<String> result = service.getBackgroundImageUrl();
            assertThat(result).isEmpty();
        }

        @Test
        void shouldReturnEmptyWhenZoneConfigIsNull() {
            IdentityZone zone = new IdentityZone();
            zone.setId(ZONE_ID);
            zone.setConfig(null);
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.set(zone);
            java.util.Optional<String> result = service.getBackgroundImageUrl();
            assertThat(result).isEmpty();
        }

        @Test
        void shouldReturnEmptyWhenBrandingIsNull() {
            IdentityZone zone = new IdentityZone();
            zone.setId(ZONE_ID);
            IdentityZoneConfiguration config = new IdentityZoneConfiguration();
            config.setBranding(null);
            zone.setConfig(config);
            org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.set(zone);
            java.util.Optional<String> result = service.getBackgroundImageUrl();
            assertThat(result).isEmpty();
        }
    }
}
