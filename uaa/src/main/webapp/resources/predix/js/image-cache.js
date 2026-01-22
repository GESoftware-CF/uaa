/**
 * Preload and cache background image to prevent reloading on page navigation
 */
(function() {
    'use strict';
    
    // Wait for DOM to be ready before preloading image
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', preloadBackgroundImage);
    } else {
        preloadBackgroundImage();
    }
    
    function preloadBackgroundImage() {
        try {
            // Preload background image using absolute path
            const backgroundImageUrl = '/resources/predix/images/background-image.png';
            const img = new Image();
            img.src = backgroundImageUrl;
            
            // Store in browser cache by forcing a load
            img.onload = function() {
                console.log('Background image cached successfully');
            };
            
            img.onerror = function() {
                console.warn('Failed to cache background image');
            };
        } catch (e) {
            // Silently fail if there's any error
            console.warn('Image cache initialization failed:', e);
        }
    }
})();
