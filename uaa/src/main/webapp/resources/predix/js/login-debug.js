/**
 * Login Page Debug Logger
 * Logs Thymeleaf variables passed from the server for debugging purposes
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
        const debugEl = document.getElementById('uaa-debug-data');
        
        if (!debugEl) {
            console.warn('UAA Debug Data element not found');
            return;
        }
        
        try {
            const customerIdpWebDomains = JSON.parse(debugEl.dataset.customerIdpDomains || '[]');
            const idpDefinitions = JSON.parse(debugEl.dataset.idpDefinitions || '[]');
            const oauthLinks = JSON.parse(debugEl.dataset.oauthLinks || '{}');
            const fieldUsernameShow = debugEl.dataset.fieldUsernameShow === 'true';
            const linkCreateAccountShow = debugEl.dataset.linkCreateAccountShow === 'true';
            
            console.log('=== Login Page Debug Info ===');
            console.log('customerIdpWebDomains:', customerIdpWebDomains);
            console.log('idpDefinitions:', idpDefinitions);
            console.log('oauthLinks:', oauthLinks);
            console.log('fieldUsernameShow:', fieldUsernameShow);
            console.log('linkCreateAccountShow:', linkCreateAccountShow);
            console.log('==============================');
            
            // Optional: Pretty print for better readability
            if (idpDefinitions && idpDefinitions.length > 0) {
                console.log('IDP Definitions (formatted):', JSON.stringify(idpDefinitions, null, 2));
            }
            
            if (oauthLinks && Object.keys(oauthLinks).length > 0) {
                console.log('OAuth Links (formatted):', JSON.stringify(oauthLinks, null, 2));
            }
        } catch (error) {
            console.error('Error parsing UAA debug data:', error);
        }
    }
})();
