/**
 * Preload and cache background image to prevent reloading on page navigation
 */
(function() {
    'use strict';
    
    // Preload background image
    const backgroundImageUrl = '../images/background-image.png';
    const img = new Image();
    img.src = backgroundImageUrl;
    
    // Store in browser cache by forcing a load
    img.onload = function() {
        console.log('Background image cached successfully');
    };
    
    img.onerror = function() {
        console.warn('Failed to cache background image');
    };
})();
