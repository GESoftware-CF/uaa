package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.login.BackgroundImageUrlProvider;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * {@link BackgroundImageUrlProvider} implementation that resolves the background image URL
 * from the current identity zone's branding configuration.
 *
 * <p>The URL is stored in {@code identity_zone.config.branding.backgroundImageUrl} by
 * {@link BackgroundImageService} at upload time.  When no URL is present (e.g. the zone
 * has never had a custom background image uploaded), {@link Optional#empty()} is returned
 * so the login page falls back to the default static image.
 */
@Component
public class S3BackgroundImageUrlProvider implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(S3BackgroundImageUrlProvider.class);

    @Override
    public Optional<String> getBackgroundImageUrl() {
        try {
            IdentityZone zone = IdentityZoneHolder.get();
            IdentityZoneConfiguration config = zone.getConfig();
            if (config == null) {
                return Optional.empty();
            }
            BrandingInformation branding = config.getBranding();
            if (branding == null) {
                return Optional.empty();
            }
            String url = branding.getBackgroundImageUrl();
            if (url == null || url.isBlank()) {
                return Optional.empty();
            }
            logger.debug("Resolved background image URL for zone={}: {}", zone.getId(), url);
            return Optional.of(url);
        } catch (Exception e) {
            logger.warn("Failed to resolve background image URL; falling back to default", e);
            return Optional.empty();
        }
    }
}

