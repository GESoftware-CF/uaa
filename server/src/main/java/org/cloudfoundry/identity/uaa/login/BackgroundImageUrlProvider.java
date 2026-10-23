package org.cloudfoundry.identity.uaa.login;

import java.util.Optional;

/**
 * Strategy interface for resolving the background image URL for the current identity zone.
 *
 * <p>Implementations may read the URL from the zone's branding configuration, an S3 bucket,
 * or any other source.  When no image URL is available the provider should return
 * {@link Optional#empty()} so the login page falls back to the default static image.
 */
@FunctionalInterface
public interface BackgroundImageUrlProvider {

    /**
     * Return the background image URL for the currently active identity zone, or
     * {@link Optional#empty()} if none is configured.
     *
     * @return an {@link Optional} containing the image URL, or empty if unavailable
     */
    Optional<String> getBackgroundImageUrl();
}

