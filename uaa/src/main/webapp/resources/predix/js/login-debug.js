/**
 * Login Page Debug Logger
 * Logs Thymeleaf variables passed from the server for debugging purposes
 * Uses application/json script tag to avoid CSP issues
 */
(function() {
    'use strict';
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', logDebugInfo);
    } else {
        logDebugInfo();
    }
    
    function logDebugInfo() {
        const debugScript = document.getElementById('uaa-debug-data');
        
        if (!debugScript) {
            console.warn('UAA Debug Data script not found');
            return;
        }
        
        try {
            const data = JSON.parse(debugScript.textContent);
            
            console.log('=== Login Page Debug Info ===');
            console.log('customerIdpWebDomains:', data.customerIdpWebDomains);
            console.log('idpDefinitions:', data.idpDefinitions);
            console.log('oauthLinks:', data.oauthLinks);
            console.log('fieldUsernameShow:', data.fieldUsernameShow);
            console.log('linkCreateAccountShow:', data.linkCreateAccountShow);
            console.log('==============================');
            
            // Optional: Pretty print for better readability
            if (data.idpDefinitions && Array.isArray(data.idpDefinitions) && data.idpDefinitions.length > 0) {
                console.log('IDP Definitions (formatted):', JSON.stringify(data.idpDefinitions, null, 2));
            }
            
            if (data.oauthLinks && typeof data.oauthLinks === 'object' && Object.keys(data.oauthLinks).length > 0) {
                console.log('OAuth Links (formatted):', JSON.stringify(data.oauthLinks, null, 2));
            }
        } catch (error) {
            console.error('Error parsing UAA debug data:', error);
            console.error('Script content:', debugScript.textContent);
        }
    }
})();
