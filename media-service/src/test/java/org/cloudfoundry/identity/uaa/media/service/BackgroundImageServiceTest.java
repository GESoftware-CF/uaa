package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.event.BackgroundImageAuditPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.InputStream;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BackgroundImageServiceTest {
    private static final String ZONE_ID = "test-zone";
    private static final String BUCKET = "test-bucket";
    private static final String BASE_PATH = "int/iam/uaa/background_images";
    private static final String CLOUDFRONT = "images.example.com";
    private static final String PNG_TYPE = "image/png";
    private static final String OLD_REFERENCE = ZONE_ID + "/1792387343803-97c57c94.jpg";
    private static final String OLD_KEY = BASE_PATH + "/" + OLD_REFERENCE;
    private static final byte[] IMAGE = "image bytes".getBytes();
    private static final long MAX_SIZE = 5 * 1024 * 1024L;

    @Mock private S3StorageManager storage;
    @Mock private IdentityZoneProvisioning zones;
    @Mock private BackgroundImageAuditPublisher auditPublisher;
    private BackgroundImageService service;

    @BeforeEach
    void setUp() {
        service = new BackgroundImageService(storage, zones, BUCKET, 1, MAX_SIZE,
                CLOUDFRONT, BASE_PATH, auditPublisher);
        IdentityZoneHolder.set(zone(null));
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.set(zone(null));
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void uploadsNewImageAndAuditsAfterZoneUpdate() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        MockMultipartFile file = png();

        service.uploadBackgroundImage(file, ZONE_ID);

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(storage).upload(eq(BUCKET), key.capture(), any(InputStream.class), eq((long) IMAGE.length), eq(PNG_TYPE));
        assertThat(key.getValue()).matches(BASE_PATH + "/" + ZONE_ID + "/[0-9]{10,}-[0-9a-f]{8}\\.png");
        ArgumentCaptor<IdentityZone> updated = ArgumentCaptor.forClass(IdentityZone.class);
        InOrder order = inOrder(zones, auditPublisher);
        order.verify(zones).update(updated.capture());
        order.verify(auditPublisher).uploaded(eq(ZONE_ID), eq("test-subdomain"), anyString(),
                eq(updated.getValue().getConfig().getBranding().getBackgroundImageUrl()),
                eq((long) IMAGE.length), eq(PNG_TYPE));
        verify(auditPublisher, never()).replaced(anyString(), anyString(), anyString(), anyString(),
            anyString(), anyBoolean(), anyLong(), anyString());
        verify(auditPublisher, never()).failed(any(), anyString(), anyString(), anyString(), anyString(),
                anyLong(), anyString(), anyString(), any());
    }

    @Test
    void replacementAuditsSuccessfulOldObjectDelete() throws Exception {
        IdentityZone zone = zone(OLD_REFERENCE);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);

        service.uploadBackgroundImage(png(), ZONE_ID);

        ArgumentCaptor<String> newReference = ArgumentCaptor.forClass(String.class);
        verify(auditPublisher).replaced(eq(ZONE_ID), eq("test-subdomain"), anyString(),
                newReference.capture(), eq(OLD_REFERENCE), eq(true), eq((long) IMAGE.length), eq(PNG_TYPE));
        verify(storage).delete(BUCKET, OLD_KEY);
        assertThat(newReference.getValue()).startsWith(ZONE_ID + "/");
    }

    @Test
    void replacementAuditsFailedOldObjectDeleteButSucceeds() throws Exception {
        when(zones.retrieve(ZONE_ID)).thenReturn(zone(OLD_REFERENCE));
        doThrow(new RuntimeException("S3 unavailable")).when(storage).delete(BUCKET, OLD_KEY);

        service.uploadBackgroundImage(png(), ZONE_ID);

        verify(auditPublisher).replaced(eq(ZONE_ID), eq("test-subdomain"), anyString(), anyString(),
                eq(OLD_REFERENCE), eq(false), eq((long) IMAGE.length), eq(PNG_TYPE));
    }

    @Test
    void s3UploadFailureAuditsAndPropagatesFailure() throws Exception {
        RuntimeException s3Failure = new RuntimeException("S3 failure");
        doThrow(s3Failure).when(storage).upload(anyString(), anyString(), any(InputStream.class), anyLong(), anyString());

        assertThatThrownBy(() -> service.uploadBackgroundImage(png(), ZONE_ID))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(error -> assertThat(((ResponseStatusException) error).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_GATEWAY));

        verify(auditPublisher).failed(eq(AuditEventType.BackgroundImageUploadedEvent), eq(ZONE_ID), eq("test-subdomain"),
                anyString(), anyString(), eq((long) IMAGE.length), eq(PNG_TYPE), eq("s3Upload"), any(Exception.class));
        verify(zones, never()).update(any());
    }

    @Test
    void dbUpdateFailureDeletesNewObjectAuditsAndRethrowsOriginal() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        RuntimeException dbFailure = new RuntimeException("DB failure");
        doThrow(dbFailure).when(zones).update(zone);

        assertThatThrownBy(() -> service.uploadBackgroundImage(png(), ZONE_ID)).isSameAs(dbFailure);

        ArgumentCaptor<String> uploadedKey = ArgumentCaptor.forClass(String.class);
        verify(storage).upload(eq(BUCKET), uploadedKey.capture(), any(InputStream.class), anyLong(), eq(PNG_TYPE));
        verify(storage).delete(BUCKET, uploadedKey.getValue());
        verify(auditPublisher).failed(eq(AuditEventType.BackgroundImageUploadedEvent), eq(ZONE_ID),
                eq("test-subdomain"), anyString(), anyString(), eq((long) IMAGE.length), eq(PNG_TYPE),
                eq("dbUpdate"), eq(dbFailure));
    }

    @Test
    void deleteClearsDbBeforeDeletingAndAuditing() {
        IdentityZone zone = zone(OLD_REFERENCE);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);

        assertThat(service.deleteBackgroundImage(ZONE_ID)).isTrue();

        InOrder order = inOrder(zones, storage, auditPublisher);
        order.verify(zones).update(zone);
        order.verify(storage).delete(BUCKET, OLD_KEY);
        order.verify(auditPublisher).deleted(eq(ZONE_ID), eq("test-subdomain"), anyString(), eq(OLD_REFERENCE), eq(true));
        assertThat(zone.getConfig().getBranding().getBackgroundImageUrl()).isNull();
    }

    @Test
    void deleteS3FailureStillSucceedsAndAuditsFalse() {
        when(zones.retrieve(ZONE_ID)).thenReturn(zone(OLD_REFERENCE));
        doThrow(new RuntimeException("S3 unavailable")).when(storage).delete(BUCKET, OLD_KEY);

        assertThat(service.deleteBackgroundImage(ZONE_ID)).isTrue();

        verify(auditPublisher).deleted(eq(ZONE_ID), eq("test-subdomain"), anyString(), eq(OLD_REFERENCE), eq(false));
    }

    @Test
    void deleteDatabaseFailureAuditsAndRethrowsWithoutS3Delete() {
        IdentityZone zone = zone(OLD_REFERENCE);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        RuntimeException dbFailure = new RuntimeException("DB failure");
        doThrow(dbFailure).when(zones).update(zone);

        assertThatThrownBy(() -> service.deleteBackgroundImage(ZONE_ID)).isSameAs(dbFailure);

        verify(auditPublisher).failed(eq(AuditEventType.BackgroundImageDeletedEvent), eq(ZONE_ID),
                eq("test-subdomain"), anyString(), eq(OLD_REFERENCE), eq(0L), eq("-"), eq("dbUpdate"), eq(dbFailure));
        verifyNoInteractions(storage);
    }

    @Test
    void deleteWithoutImageReturnsFalseWithoutPublishing() {
        when(zones.retrieve(ZONE_ID)).thenReturn(zone(null));

        assertThat(service.deleteBackgroundImage(ZONE_ID)).isFalse();

        verifyNoInteractions(storage, auditPublisher);
    }

    @Test
    void validationRejectionsDoNotPublishAudit() {
        MockMultipartFile unsupported = new MockMultipartFile("file", "image.gif", "image/gif", IMAGE);

        assertThatThrownBy(() -> service.uploadBackgroundImage(unsupported, ZONE_ID))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(error -> assertThat(((ResponseStatusException) error).getStatusCode())
                        .isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE));

        verifyNoInteractions(storage, zones, auditPublisher);
    }

    @ParameterizedTest
    @ValueSource(longs = {0, MAX_SIZE + 1})
    void sizeValidationRejectionsDoNotPublishAudit(long size) {
        MockMultipartFile file = new MockMultipartFile("file", "image.png", PNG_TYPE, IMAGE) {
            @Override
            public long getSize() {
                return size;
            }
        };

        assertThatThrownBy(() -> service.uploadBackgroundImage(file, ZONE_ID))
                .isInstanceOf(ResponseStatusException.class);

        verifyNoInteractions(storage, zones, auditPublisher);
    }

    @ParameterizedTest
    @ValueSource(strings = {"../other", "zone/other", "zone%2fother", "invalid zone"})
    void zoneValidationRejectionsDoNotPublishAudit(String zoneId) {
        assertThatThrownBy(() -> service.uploadBackgroundImage(png(), zoneId))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(error -> assertThat(((ResponseStatusException) error).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST));

        verifyNoInteractions(storage, zones, auditPublisher);
    }

    @Test
    void auditPublisherFailureDoesNotChangeSuccessfulUpload() throws Exception {
        when(zones.retrieve(ZONE_ID)).thenReturn(zone(null));
        doThrow(new RuntimeException("audit unavailable")).when(auditPublisher)
                .uploaded(anyString(), anyString(), anyString(), anyString(), anyLong(), anyString());

        service.uploadBackgroundImage(png(), ZONE_ID);

        verify(zones).update(any());
    }

    @Test
    void uploaderNameComesFromSecurityContext() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("zone-admin", "n/a"));

        service.uploadBackgroundImage(png(), ZONE_ID);

        ArgumentCaptor<IdentityZone> updated = ArgumentCaptor.forClass(IdentityZone.class);
        verify(zones).update(updated.capture());
        assertThat(updated.getValue().getConfig().getBranding().getBackgroundImageUploadedBy())
                .isEqualTo("zone-admin");
    }

    @Test
    void uploaderIsUnknownWithoutSecurityContext() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);

        service.uploadBackgroundImage(png(), ZONE_ID);

        ArgumentCaptor<IdentityZone> updated = ArgumentCaptor.forClass(IdentityZone.class);
        verify(zones).update(updated.capture());
        assertThat(updated.getValue().getConfig().getBranding().getBackgroundImageUploadedBy()).isEqualTo("unknown");
    }

    @Test
    void uploadPreservesOtherBrandingFields() throws Exception {
        IdentityZone zone = zone(null);
        zone.getConfig().getBranding().setCompanyName("Acme");
        zone.getConfig().getBranding().setProductLogo("logo-data");
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);

        service.uploadBackgroundImage(png(), ZONE_ID);

        assertThat(zone.getConfig().getBranding().getCompanyName()).isEqualTo("Acme");
        assertThat(zone.getConfig().getBranding().getProductLogo()).isEqualTo("logo-data");
    }

    @Test
    void uploadCreatesConfigAndBrandingWhenZoneHasNone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setId(ZONE_ID);
        zone.setSubdomain("test-subdomain");
        zone.setConfig(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);

        service.uploadBackgroundImage(png(), ZONE_ID);

        assertThat(zone.getConfig()).isNotNull();
        assertThat(zone.getConfig().getBranding()).isNotNull();
        assertThat(zone.getConfig().getBranding().getBackgroundImageUrl()).startsWith(ZONE_ID + "/");
    }

    @Test
    void getBackgroundImageUrlBuildsCloudFrontUrlFromValidStoredReference() {
        IdentityZoneHolder.set(zone(OLD_REFERENCE));

        assertThat(service.getBackgroundImageUrl())
                .isEqualTo(Optional.of("https://" + CLOUDFRONT + "/" + OLD_KEY));
    }

    @ParameterizedTest
    @ValueSource(strings = {"  ", "another-zone/1792387343803-97c57c94.jpg",
            "https://legacy.example.com/image.jpg"})
    void getBackgroundImageUrlUsesDefaultForBlankForeignAndLegacyValues(String value) {
        IdentityZoneHolder.set(zone(value));

        assertThat(service.getBackgroundImageUrl())
                .isEqualTo(Optional.of("https://" + CLOUDFRONT + "/" + BASE_PATH + "/defaultimage.jpg"));
    }

    @Test
    void getBackgroundImageUrlUsesDefaultForNullValue() {
        IdentityZoneHolder.set(zone(null));

        assertThat(service.getBackgroundImageUrl())
                .isEqualTo(Optional.of("https://" + CLOUDFRONT + "/" + BASE_PATH + "/defaultimage.jpg"));
    }

    @Test
    void getBackgroundImageUrlUsesDefaultWhenZoneHolderThrows() {
        try (var holder = mockStatic(IdentityZoneHolder.class)) {
            holder.when(IdentityZoneHolder::get).thenThrow(new IllegalStateException("zone unavailable"));

            assertThat(service.getBackgroundImageUrl())
                    .isEqualTo(Optional.of("https://" + CLOUDFRONT + "/" + BASE_PATH + "/defaultimage.jpg"));
        }
    }

    @Test
    void retriesTransientS3FailureThenSucceedsWithoutFailureAudit() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        AtomicInteger attempts = new AtomicInteger();
        S3Exception unavailable = S3Exception.builder().statusCode(503).message("unavailable").build();
        doAnswer(invocation -> {
            if (attempts.incrementAndGet() == 1) {
                throw unavailable;
            }
            return null;
        }).when(storage).upload(eq(BUCKET), anyString(), any(InputStream.class), anyLong(), eq(PNG_TYPE));

        service.uploadBackgroundImage(png(), ZONE_ID);

        assertThat(attempts).hasValue(2);
        verify(auditPublisher, never()).failed(any(), anyString(), anyString(), anyString(), anyString(),
                anyLong(), anyString(), anyString(), any());
    }

    @Test
    void threeTransientS3FailuresAuditAndReturnServiceUnavailable() throws Exception {
        IdentityZone zone = zone(null);
        when(zones.retrieve(ZONE_ID)).thenReturn(zone);
        AtomicInteger attempts = new AtomicInteger();
        S3Exception unavailable = S3Exception.builder().statusCode(503).message("unavailable").build();
        doAnswer(invocation -> {
            attempts.incrementAndGet();
            throw unavailable;
        }).when(storage).upload(eq(BUCKET), anyString(), any(InputStream.class), anyLong(), eq(PNG_TYPE));

        assertThatThrownBy(() -> service.uploadBackgroundImage(png(), ZONE_ID))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(error -> assertThat(((ResponseStatusException) error).getStatusCode())
                        .isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));

        assertThat(attempts).hasValue(3);
        verify(auditPublisher).failed(eq(AuditEventType.BackgroundImageUploadedEvent), eq(ZONE_ID), eq("test-subdomain"),
                anyString(), anyString(), eq((long) IMAGE.length), eq(PNG_TYPE), eq("s3Upload"), eq(unavailable));
    }

    @Test
    void accessDeniedIsNotRetriedAndReturnsBadGateway() throws Exception {
        when(zones.retrieve(ZONE_ID)).thenReturn(zone(null));
        AtomicInteger attempts = new AtomicInteger();
        S3Exception denied = S3Exception.builder().statusCode(403).message("denied").build();
        doAnswer(invocation -> {
            attempts.incrementAndGet();
            throw denied;
        }).when(storage).upload(eq(BUCKET), anyString(), any(InputStream.class), anyLong(), eq(PNG_TYPE));

        assertThatThrownBy(() -> service.uploadBackgroundImage(png(), ZONE_ID))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(error -> assertThat(((ResponseStatusException) error).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_GATEWAY));

        assertThat(attempts).hasValue(1);
        verify(auditPublisher).failed(eq(AuditEventType.BackgroundImageUploadedEvent), eq(ZONE_ID), eq("test-subdomain"),
                anyString(), anyString(), eq((long) IMAGE.length), eq(PNG_TYPE), eq("s3Upload"), eq(denied));
    }

    @Test
    void constructorRejectsInvalidMinimumAndMaximum() {
        assertThatThrownBy(() -> new BackgroundImageService(storage, zones, BUCKET, MAX_SIZE + 1,
                MAX_SIZE, CLOUDFRONT, BASE_PATH, auditPublisher)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BackgroundImageService(storage, zones, BUCKET, 0,
                MAX_SIZE, CLOUDFRONT, BASE_PATH, auditPublisher)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructorRejectsUnsafeBasePathAndCloudFrontScheme() {
        assertThatThrownBy(() -> new BackgroundImageService(storage, zones, BUCKET, 1,
                MAX_SIZE, CLOUDFRONT, "/" + BASE_PATH, auditPublisher)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BackgroundImageService(storage, zones, BUCKET, 1,
                MAX_SIZE, CLOUDFRONT, "safe/../path", auditPublisher)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BackgroundImageService(storage, zones, BUCKET, 1,
                MAX_SIZE, "https://" + CLOUDFRONT, BASE_PATH, auditPublisher)).isInstanceOf(IllegalArgumentException.class);
    }

    private static MockMultipartFile png() {
        return new MockMultipartFile("file", "image.png", PNG_TYPE, IMAGE);
    }

    private static IdentityZone zone(String reference) {
        IdentityZone zone = new IdentityZone();
        zone.setId(ZONE_ID);
        zone.setSubdomain("test-subdomain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        BrandingInformation branding = new BrandingInformation();
        branding.setBackgroundImageUrl(reference);
        config.setBranding(branding);
        zone.setConfig(config);
        return zone;
    }
}