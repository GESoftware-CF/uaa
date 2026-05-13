package org.cloudfoundry.identity.uaa.media.service;

import org.cloudfoundry.identity.uaa.login.BackgroundImageUrlProvider;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * {@link BackgroundImageUrlProvider} implementation that reads the background image URL
 * directly from the identity zone's config ({@code config.branding.backgroundImageUrl}).
 *
 * <p>The URL is stored when an image is uploaded via the POST API. No separate DB table
 * or GET API call is needed — the URL is fetched from the in-memory zone config.
 *
 * <p><b>Fallback behaviour:</b> When no zone-specific image is configured, and a default
 * S3 URL is provided via the {@code background-image.default-url} property, that default
 * URL is returned so the login page always shows an image.
 */
@Component
public class S3BackgroundImageUrlProvider implements BackgroundImageUrlProvider {

    private static final Logger logger = LoggerFactory.getLogger(S3BackgroundImageUrlProvider.class);

    /**
     * Optional default background image URL (public S3 URL).
     * Set via {@code background-image.default-url} in uaa.yml / environment.
     * If blank or absent, the Thymeleaf template falls back to the static {@code cf.png}.
     */
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
            if (config != null) {
                BrandingInformation branding = config.getBranding();
                if (branding != null) {
                    String url = branding.getBackgroundImageUrl();
                    if (url != null && !url.isBlank()) {
                        logger.debug("Resolved zone-specific background image URL for zone '{}': {}",
                                zone.getId(), url);
                        return Optional.of(url);
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to resolve zone background image URL; will try default", e);
        }

        // Fallback: return the configured default S3 URL (if any)
        if (defaultImageUrl != null && !defaultImageUrl.isBlank()) {
            logger.debug("No zone-specific background image found; using default URL: {}", defaultImageUrl);
            return Optional.of(defaultImageUrl);
        }

        // No default configured — let the Thymeleaf template use its own static fallback
        return Optional.empty();
    }
}
