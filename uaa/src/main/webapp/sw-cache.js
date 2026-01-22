// Service Worker for caching static resources
const CACHE_NAME = 'uaa-static-cache-v2';
const urlsToCache = [
    '/resources/predix/images/background-image.jpg',
    '/resources/predix/stylesheets/predix-styles.css',
    '/resources/predix/stylesheets/roboto.css',
    '/resources/predix/stylesheets/predix-card-styles.css'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                return cache.addAll(urlsToCache);
            })
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                // Cache hit - return response from cache
                if (response) {
                    return response;
                }
                // Clone the request
                const fetchRequest = event.request.clone();
                
                return fetch(fetchRequest).then(
                    function(response) {
                        // Check if valid response
                        if(!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        
                        // Check if it's a static resource to cache
                        const requestUrl = new URL(event.request.url);
                        if (requestUrl.pathname.includes('/resources/predix/')) {
                            const responseToCache = response.clone();
                            caches.open(CACHE_NAME)
                                .then(function(cache) {
                                    cache.put(event.request, responseToCache);
                                });
                        }
                        
                        return response;
                    }
                );
            })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});
