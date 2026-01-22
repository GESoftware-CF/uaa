// Register Service Worker for caching
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/resources/sw-cache.js', { scope: '/resources/' })
            .then(function(registration) {
                console.log('Service Worker registered successfully');
            })
            .catch(function(err) {
                console.log('Service Worker registration failed:', err);
            });
    });
}
