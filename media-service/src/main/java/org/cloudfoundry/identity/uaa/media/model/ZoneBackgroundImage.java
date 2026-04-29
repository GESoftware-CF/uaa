package org.cloudfoundry.identity.uaa.media.model;

import java.util.Objects;

/**
 * Represents the currently active background image for an identity zone.
 *
 * <p>This is operational data — it tells the system which S3 key to load when
 * rendering the login page for a given zone. One row per zone (upserted on upload,
 * deleted on delete). No audit history is stored here.
 */
public final class ZoneBackgroundImage {

    private final String zoneId;
    private final String s3Key;

    public ZoneBackgroundImage(String zoneId, String s3Key) {
        this.zoneId = Objects.requireNonNull(zoneId, "zoneId must not be null");
        this.s3Key  = Objects.requireNonNull(s3Key,  "s3Key must not be null");
    }

    /**
     * @return the identity zone ID this image belongs to
     */
    public String getZoneId() {
        return zoneId;
    }

    /**
     * @return the S3 object key for this zone's active background image
     */
    public String getS3Key() {
        return s3Key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ZoneBackgroundImage other)) return false;
        return Objects.equals(zoneId, other.zoneId) && Objects.equals(s3Key, other.s3Key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zoneId, s3Key);
    }

    @Override
    public String toString() {
        return "ZoneBackgroundImage{zoneId='" + zoneId + "', s3Key='" + s3Key + "'}";
    }
}

