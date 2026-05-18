package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.login.BackgroundImageUrlProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Resolves the background image URL for the current identity zone.
 *
 * <p>Reads {@code config.branding.backgroundImageUrl} stored on upload.
 * Falls back to {@code background-image.default-url} when no custom image has been uploaded.
 */
@Component
public class S3BackgroundImageUrlProvider implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(S3BackgroundImageUrlProvider.class);

    private final String defaultImageUrl;

    public S3BackgroundImageUrlProvider(
            @Value("${background-image.default-url:}") String defaultImageUrl) {
        this.defaultImageUrl = defaultImageUrl;
    }

    @Override
    public Optional<String> getBackgroundImageUrl() {
        try {
            IdentityZone zone = IdentityZoneHolder.get();
            IdentityZoneConfiguration config = zone.getConfig();
            if (config != null && config.getBranding() != null) {
                String url = config.getBranding().getBackgroundImageUrl();
                if (url != null && !url.isBlank()) {
                    logger.debug("Resolved background image URL for zone '{}': {}", zone.getId(), url);
                    return Optional.of(url);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to resolve zone background image URL; will try default", e);
        }

        if (defaultImageUrl != null && !defaultImageUrl.isBlank()) {
            logger.debug("No zone-specific background image; using default URL: {}", defaultImageUrl);
            return Optional.of(defaultImageUrl);
        }

        return Optional.empty();
    }
}
