// Format last login time using browser's locale
(function() {
    'use strict';
    
    function formatLastLoginTime() {
        var element = document.getElementById('last_login_time');
        if (element && element.hasAttribute('data-timestamp')) {
            var timestamp = parseInt(element.getAttribute('data-timestamp'), 10);
            if (!isNaN(timestamp)) {
                var date = new Date(timestamp);
                element.textContent = date.toLocaleString();
            }
        }
    }
    
    // Execute when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', formatLastLoginTime);
    } else {
        formatLastLoginTime();
    }
})();
