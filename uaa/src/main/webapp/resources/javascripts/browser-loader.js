/*
 * browser-loader.js
 *
 * Loads CSS and Babel-transpiled JS for the correct browser target.
 * - CSS: single set of files (already contains vendor prefixes for IE11 + modern)
 * - JS:  Babel produces dist/modern/ (lean ES2020) and dist/legacy/ (ES5 + polyfills for IE11)
 *
 * The asset base path is supplied by the server via the script element's
 * data-asset-base attribute (Thymeleaf-rendered). It is validated against a
 * strict allowlist — no user-supplied or URL-derived input is accepted.
 */
(function () {
    /* ------------------------------------------------------------------ */
    /* 1. Resolve asset base from the server-rendered data attribute only  */
    /* ------------------------------------------------------------------ */
    var scripts = document.getElementsByTagName('script');
    var thisScript = scripts[scripts.length - 1];
    var rawBase = thisScript.getAttribute('data-asset-base');

    /* Allowlist: only these server-known paths are permitted.
       Any other value falls back to the safe default,
       preventing path traversal or external URL injection. */
    var ALLOWED_BASES = [
        '/resources/oss',
        '/resources/predix'
    ];
    var assetBase = '/resources/oss'; /* safe default */
    for (var a = 0; a < ALLOWED_BASES.length; a++) {
        if (rawBase === ALLOWED_BASES[a]) {
            assetBase = ALLOWED_BASES[a];
            break;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 2. Detect IE11 — browser-internal only, no user input involved     */
    /* ------------------------------------------------------------------ */
    var isIE11 = !!window.MSInputMethodContext && !!document.documentMode;

    /* ------------------------------------------------------------------ */
    /* 3. Load CSS — one set of files works for both IE11 and modern      */
    /* ------------------------------------------------------------------ */
    var cssFiles = [
        assetBase + '/stylesheets/application.css',
        assetBase + '/stylesheets/predix-styles.css',
        assetBase + '/stylesheets/predix-card-styles.css'
    ];

    var head = document.head || document.getElementsByTagName('head')[0];
    for (var i = 0; i < cssFiles.length; i++) {
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = cssFiles[i];
        head.appendChild(link);
    }

    /* ------------------------------------------------------------------ */
    /* 4. Load JS — Babel dist: legacy (ES5+polyfills) or modern (ES2020) */
    /* ------------------------------------------------------------------ */
    var jsBuild = isIE11 ? 'legacy' : 'modern';
    var jsFile = '/resources/javascripts/dist/' + jsBuild + '/last_login_time.js';

    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.src = jsFile;
    head.appendChild(script);
}());
