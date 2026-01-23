// Service Worker for aggressive caching of background images
// This ensures instant loading on repeat visits (login.do -> reset password)

const CACHE_NAME = 'uaa-static-v1';
const CRITICAL_ASSETS = [
  '/resources/predix/images/background-image.webp',
  '/resources/predix/images/background-image.png',
  '/resources/predix/stylesheets/predix-styles.css',
  '/resources/predix/images/predix-word.svg'
];

// Install event - cache critical assets immediately
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[ServiceWorker] Caching critical assets');
        return cache.addAll(CRITICAL_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - Cache-first strategy for images, network-first for pages
self.addEventListener('fetch', (event) => {
  const { request } = event;
  
  // Cache-first strategy for static assets (images, CSS, fonts)
  if (request.url.match(/\.(png|jpg|jpeg|webp|svg|css|woff2?|ttf)$/)) {
    event.respondWith(
      caches.match(request)
        .then((cachedResponse) => {
          if (cachedResponse) {
            console.log('[ServiceWorker] Serving from cache:', request.url);
            return cachedResponse;
          }
          
          return fetch(request).then((response) => {
            // Don't cache if not successful
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(request, responseToCache);
              });
            
            return response;
          });
        })
    );
  }
});
