package org.cloudfoundry.identity.uaa.media.repository;

import org.cloudfoundry.identity.uaa.media.model.ZoneBackgroundImage;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * JDBC repository for {@link ZoneBackgroundImage}.
 *
 * <p>Maintains one row per identity zone — the zone's currently active background image.
 * On upload the row is upserted (INSERT … ON CONFLICT UPDATE for PostgreSQL / REPLACE for MySQL).
 * On delete the row is removed. No history is kept.
 *
 * <p>Follows the UAA convention of using {@link JdbcTemplate} directly (no Spring Data JPA).
 */
@Repository
public class ZoneBackgroundImageRepository {

    // language-neutral SELECT / DELETE
    private static final String FIND_BY_ZONE =
            "SELECT zone_id, s3_key FROM background_zone_image WHERE zone_id = ?";

    private static final String DELETE_BY_ZONE =
            "DELETE FROM background_zone_image WHERE zone_id = ?";

    // PostgreSQL upsert
    private static final String UPSERT_POSTGRESQL =
            "INSERT INTO background_zone_image (zone_id, s3_key) VALUES (?, ?) "
            + "ON CONFLICT (zone_id) DO UPDATE SET s3_key = EXCLUDED.s3_key";

    // MySQL / MariaDB upsert
    private static final String UPSERT_MYSQL =
            "INSERT INTO background_zone_image (zone_id, s3_key) VALUES (?, ?) "
            + "ON DUPLICATE KEY UPDATE s3_key = VALUES(s3_key)";

    // HSQLDB upsert (MERGE)
    private static final String UPSERT_HSQLDB =
            "MERGE INTO background_zone_image AS target "
            + "USING (VALUES (?, ?)) AS source (zone_id, s3_key) "
            + "ON target.zone_id = source.zone_id "
            + "WHEN MATCHED THEN UPDATE SET target.s3_key = source.s3_key "
            + "WHEN NOT MATCHED THEN INSERT (zone_id, s3_key) VALUES (source.zone_id, source.s3_key)";

    private static final RowMapper<ZoneBackgroundImage> ROW_MAPPER =
            (rs, rowNum) -> new ZoneBackgroundImage(rs.getString("zone_id"), rs.getString("s3_key"));

    private final JdbcTemplate jdbcTemplate;
    private final String upsertSql;

    /**
     * @param jdbcTemplate the JDBC template to use
     * @param dbPlatform   database platform: {@code postgresql}, {@code mysql}, or {@code hsqldb}
     */
    public ZoneBackgroundImageRepository(JdbcTemplate jdbcTemplate,
                                         @org.springframework.beans.factory.annotation.Value(
                                                 "${spring.datasource.platform:postgresql}") String dbPlatform) {
        this.jdbcTemplate = jdbcTemplate;
        this.upsertSql = resolveUpsertSql(dbPlatform);
    }

    /**
     * Upsert the active background image for a zone.
     * If a row already exists for {@code zoneId} its {@code s3_key} is replaced.
     *
     * @param image the zone-to-s3-key mapping to persist
     */
    @Transactional
    public void save(ZoneBackgroundImage image) {
        jdbcTemplate.update(upsertSql, image.getZoneId(), image.getS3Key());
    }

    /**
     * Return the active background image record for the given zone, if one exists.
     *
     * @param zoneId the identity zone ID
     * @return the record, or {@link Optional#empty()} if no image has been uploaded for this zone
     */
    public Optional<ZoneBackgroundImage> findByZoneId(String zoneId) {
        try {
            ZoneBackgroundImage result = jdbcTemplate.queryForObject(FIND_BY_ZONE, ROW_MAPPER, zoneId);
            return Optional.ofNullable(result);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    /**
     * Remove the active background image record for the given zone.
     *
     * @param zoneId the identity zone ID
     * @return {@code true} if a row was deleted, {@code false} if no row existed
     */
    @Transactional
    public boolean deleteByZoneId(String zoneId) {
        return jdbcTemplate.update(DELETE_BY_ZONE, zoneId) > 0;
    }

    private static String resolveUpsertSql(String platform) {
        return switch (platform.toLowerCase()) {
            case "mysql", "mariadb" -> UPSERT_MYSQL;
            case "hsqldb"           -> UPSERT_HSQLDB;
            default                 -> UPSERT_POSTGRESQL;
        };
    }
}

