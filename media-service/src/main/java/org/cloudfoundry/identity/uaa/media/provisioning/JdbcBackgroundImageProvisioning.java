package org.cloudfoundry.identity.uaa.media.provisioning;

import org.cloudfoundry.identity.uaa.media.model.BackgroundImage;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * JDBC implementation of BackgroundImageProvisioning.
 * Uses Spring JdbcTemplate following UAA's data access patterns.
 */
@Repository
public class JdbcBackgroundImageProvisioning implements BackgroundImageProvisioning {

    private final JdbcTemplate jdbcTemplate;
    private final TimeService timeService;

    private static final String TABLE_NAME = "background_images";
    
    private static final String INSERT_SQL = 
        "INSERT INTO " + TABLE_NAME + " (" +
        "id, identity_zone_id, uploaded_by, original_filename, storage_bucket, storage_key, " +
        "mime_type, size_bytes, created, last_modified, deleted_at" +
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    private static final String SELECT_BY_ID_SQL = 
        "SELECT * FROM " + TABLE_NAME + " WHERE id = ?";
    
    private static final String SELECT_BY_ZONE_SQL = 
        "SELECT * FROM " + TABLE_NAME + " WHERE identity_zone_id = ? AND deleted_at IS NULL";
    
    private static final String EXISTS_BY_ZONE_SQL = 
        "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE identity_zone_id = ? AND deleted_at IS NULL";
    
    private static final String SOFT_DELETE_SQL = 
        "UPDATE " + TABLE_NAME + " SET deleted_at = ?, last_modified = ? WHERE id = ?";
    
    private static final String UPDATE_SQL = 
        "UPDATE " + TABLE_NAME + " SET " +
        "uploaded_by = ?, original_filename = ?, storage_bucket = ?, storage_key = ?, " +
        "mime_type = ?, size_bytes = ?, last_modified = ? " +
        "WHERE id = ?";
    
    private static final String SELECT_ALL_BY_ZONE_SQL = 
        "SELECT * FROM " + TABLE_NAME + " WHERE identity_zone_id = ? ORDER BY created DESC";

    public JdbcBackgroundImageProvisioning(JdbcTemplate jdbcTemplate, TimeService timeService) {
        this.jdbcTemplate = jdbcTemplate;
        this.timeService = timeService;
    }

    @Override
    public BackgroundImage create(BackgroundImage backgroundImage) {
        String id = UUID.randomUUID().toString();
        Date now = new Date(timeService.getCurrentTimeMillis());
        
        backgroundImage.setId(id);
        backgroundImage.setCreated(now);
        backgroundImage.setLastModified(now);
        backgroundImage.setDeletedAt(null);
        
        jdbcTemplate.update(INSERT_SQL,
            id,
            backgroundImage.getIdentityZoneId(),
            backgroundImage.getUploadedBy(),
            backgroundImage.getOriginalFilename(),
            backgroundImage.getStorageBucket(),
            backgroundImage.getStorageKey(),
            backgroundImage.getMimeType(),
            backgroundImage.getSizeBytes(),
            new Timestamp(now.getTime()),
            new Timestamp(now.getTime()),
            null
        );
        
        return backgroundImage;
    }

    @Override
    public BackgroundImage retrieve(String id) {
        try {
            return jdbcTemplate.queryForObject(SELECT_BY_ID_SQL, new BackgroundImageRowMapper(), id);
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    @Override
    public BackgroundImage retrieveByZoneId(String identityZoneId) {
        try {
            return jdbcTemplate.queryForObject(SELECT_BY_ZONE_SQL, new BackgroundImageRowMapper(), identityZoneId);
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }

    @Override
    public boolean existsByZoneId(String identityZoneId) {
        Integer count = jdbcTemplate.queryForObject(EXISTS_BY_ZONE_SQL, Integer.class, identityZoneId);
        return count != null && count > 0;
    }

    @Override
    public boolean delete(String id) {
        Date now = new Date(timeService.getCurrentTimeMillis());
        int rowsAffected = jdbcTemplate.update(SOFT_DELETE_SQL, 
            new Timestamp(now.getTime()), 
            new Timestamp(now.getTime()), 
            id
        );
        return rowsAffected > 0;
    }

    @Override
    public BackgroundImage update(BackgroundImage backgroundImage) {
        Date now = new Date(timeService.getCurrentTimeMillis());
        backgroundImage.setLastModified(now);
        
        jdbcTemplate.update(UPDATE_SQL,
            backgroundImage.getUploadedBy(),
            backgroundImage.getOriginalFilename(),
            backgroundImage.getStorageBucket(),
            backgroundImage.getStorageKey(),
            backgroundImage.getMimeType(),
            backgroundImage.getSizeBytes(),
            new Timestamp(now.getTime()),
            backgroundImage.getId()
        );
        
        return backgroundImage;
    }

    @Override
    public List<BackgroundImage> retrieveAll(String identityZoneId) {
        return jdbcTemplate.query(SELECT_ALL_BY_ZONE_SQL, new BackgroundImageRowMapper(), identityZoneId);
    }

    /**
     * RowMapper for converting ResultSet to BackgroundImage entity
     */
    private static class BackgroundImageRowMapper implements RowMapper<BackgroundImage> {
        @Override
        public BackgroundImage mapRow(ResultSet rs, int rowNum) throws SQLException {
            BackgroundImage img = new BackgroundImage();
            img.setId(rs.getString("id"));
            img.setIdentityZoneId(rs.getString("identity_zone_id"));
            img.setUploadedBy(rs.getString("uploaded_by"));
            img.setOriginalFilename(rs.getString("original_filename"));
            img.setStorageBucket(rs.getString("storage_bucket"));
            img.setStorageKey(rs.getString("storage_key"));
            img.setMimeType(rs.getString("mime_type"));
            img.setSizeBytes(rs.getLong("size_bytes"));
            img.setCreated(rs.getTimestamp("created"));
            img.setLastModified(rs.getTimestamp("last_modified"));
            
            Timestamp deletedAt = rs.getTimestamp("deleted_at");
            img.setDeletedAt(deletedAt != null ? new Date(deletedAt.getTime()) : null);
            
            return img;
        }
    }
}
