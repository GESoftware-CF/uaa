// Register Service Worker for caching
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/resources/predix/js/sw-cache.js')
            .then(function(registration) {
                console.log('Service Worker registered successfully');
            })
            .catch(function(err) {
                console.log('Service Worker registration failed:', err);
            });
    });
}
