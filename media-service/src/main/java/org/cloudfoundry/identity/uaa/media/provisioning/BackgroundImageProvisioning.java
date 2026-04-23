package org.cloudfoundry.identity.uaa.media.provisioning;

import org.cloudfoundry.identity.uaa.media.model.BackgroundImage;

import java.util.List;

/**
 * Provisioning interface for background image CRUD operations.
 * Follows UAA's provisioning pattern for consistency.
 */
public interface BackgroundImageProvisioning {
    
    /**
     * Create a new background image record
     *
     * @param backgroundImage the background image to create
     * @return the created background image with generated ID and timestamps
     */
    BackgroundImage create(BackgroundImage backgroundImage);
    
    /**
     * Retrieve a background image by its ID
     *
     * @param id the background image ID
     * @return the background image, or null if not found
     */
    BackgroundImage retrieve(String id);
    
    /**
     * Retrieve the active background image for a zone
     *
     * @param identityZoneId the identity zone ID
     * @return the active background image, or null if none exists
     */
    BackgroundImage retrieveByZoneId(String identityZoneId);
    
    /**
     * Check if a zone has an active background image
     *
     * @param identityZoneId the identity zone ID
     * @return true if an active background image exists
     */
    boolean existsByZoneId(String identityZoneId);
    
    /**
     * Soft-delete a background image by setting deleted_at timestamp
     *
     * @param id the background image ID
     * @return true if deleted successfully
     */
    boolean delete(String id);
    
    /**
     * Update an existing background image
     *
     * @param backgroundImage the background image with updated fields
     * @return the updated background image
     */
    BackgroundImage update(BackgroundImage backgroundImage);
    
    /**
     * Retrieve all background images for a zone (including soft-deleted)
     *
     * @param identityZoneId the identity zone ID
     * @return list of all background images for the zone
     */
    List<BackgroundImage> retrieveAll(String identityZoneId);
}
