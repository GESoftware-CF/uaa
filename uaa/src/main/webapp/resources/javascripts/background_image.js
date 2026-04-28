(function () {
    var CACHE_KEY = 'bg_presigned_url';
    var CACHE_TTL_MS = 5 * 24 * 60 * 60 * 1000; // 5 days

    var cache = null;

    function applyBackground(url) {
        document.documentElement.style.backgroundImage = 'url("' + url + '")';
    }

    function fetchAndCache() {
        console.log('[BgImage] Cache miss — fetching presigned URL...');
        fetch('/background_images/presigned-url?key=background_images%2Fuaa%2F8f3a4d67-2fa2-44c8-8c71-bd111b377a31_current_uaa_image.png')
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (data && data.presignedUrl) {
                    cache = { url: data.presignedUrl, expiresAt: Date.now() + CACHE_TTL_MS };
                    console.log('[BgImage] Fetched and cached. Expires at:', new Date(cache.expiresAt).toISOString());
                    applyBackground(data.presignedUrl);
                } else {
                    console.warn('[BgImage] No presigned URL returned.');
                }
            })
            .catch(function (err) { console.error('[BgImage] Fetch error:', err); });
    }

    if (cache && Date.now() < cache.expiresAt) {
        console.log('[BgImage] Cache hit. Expires at:', new Date(cache.expiresAt).toISOString());
        applyBackground(cache.url);
    } else {
        fetchAndCache();
    }
}());
