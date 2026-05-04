package org.cloudfoundry.identity.uaa.login;

import java.util.Optional;

/**
 * Strategy for resolving a background image URL for the current identity zone's login page.
 *
 * <p>Implementations are expected to be scoped per-request or to derive the zone ID from
 * the current thread-bound {@link org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder}.
 *
 * <p>This interface lives in the {@code server} module so that {@link LoginInfoEndpoint}
 * can depend on it without creating a circular module dependency with {@code media-service}.
 * The concrete implementation resides in the {@code media-service} module.
 */
public interface BackgroundImageUrlProvider {

    /**
     * Return a URL that the browser can use to load the background image for the current zone.
     *
     * <p>Implementations may return an S3 presigned URL, a data-URI, or any other absolute
     * URL that the browser can reference.  An empty {@link Optional} indicates that no
     * custom background image has been configured for the zone, and the default static asset
     * should be used instead.
     *
     * @return presigned (or otherwise resolvable) URL, or {@link Optional#empty()} if none
     */
    Optional<String> getBackgroundImageUrl();
}
