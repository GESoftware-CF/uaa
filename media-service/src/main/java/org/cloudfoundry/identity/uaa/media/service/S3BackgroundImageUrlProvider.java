package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.login.BackgroundImageUrlProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * {@link BackgroundImageUrlProvider} implementation that fetches a background image's
 * S3 key for the current identity zone from the database and returns a short-lived
 * presigned S3 GET URL.
 *
 * <p>The presigned URL is generated on every request so it is always fresh. The
 * browser receives a temporary URL that expires after {@code expiry-minutes}; the raw
 * S3 bucket URL is never exposed to the end-user's browser.
 *
 * <p>If no background image has been uploaded for the zone (i.e.
 * {@link BackgroundImageService#findS3KeyByZone(String)} returns empty) the provider
 * returns {@link Optional#empty()} and the UI falls back to the default static asset.
 */
@Component
public class S3BackgroundImageUrlProvider implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(S3BackgroundImageUrlProvider.class);

    private final BackgroundImageService backgroundImageService;
    private final long expiryMinutes;

    public S3BackgroundImageUrlProvider(
            BackgroundImageService backgroundImageService,
            @Value("${background-image.presign.expiry-minutes:60}") long expiryMinutes) {
        this.backgroundImageService = backgroundImageService;
        this.expiryMinutes = expiryMinutes;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Resolves the current zone ID from {@link IdentityZoneHolder}, looks up the
     * active S3 key in the database, and generates a presigned GET URL valid for
     * {@code background-image.presign.expiry-minutes} minutes (default: 60).
     */
    @Override
    public Optional<String> getBackgroundImageUrl() {
        String zoneId = IdentityZoneHolder.get().getId();
        try {
            return backgroundImageService.findS3KeyByZone(zoneId)
                    .map(s3Key -> {
                        String url = backgroundImageService.getPresignedUrl(zoneId, s3Key, expiryMinutes);
                        logger.debug("Resolved presigned background image URL for zone '{}': {}", zoneId, url);
                        return url;
                    });
        } catch (Exception e) {
            logger.warn("Failed to resolve background image URL for zone '{}'; falling back to default", zoneId, e);
            return Optional.empty();
        }
    }
}
