// Register Service Worker for background image caching
// This ensures instant loading across login.do, reset password, and all pages

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/resources/javascripts/sw-cache.js')
      .then((registration) => {
        console.log('[SW] Service Worker registered successfully:', registration.scope);
        
        // Check for updates periodically
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          console.log('[SW] New service worker found, installing...');
          
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'activated') {
              console.log('[SW] New service worker activated');
            }
          });
        });
      })
      .catch((error) => {
        console.log('[SW] Service Worker registration failed:', error);
      });
  });
  
  // Handle service worker updates
  let refreshing = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!refreshing) {
      refreshing = true;
      console.log('[SW] Service worker updated, reloading page...');
      window.location.reload();
    }
  });
}
