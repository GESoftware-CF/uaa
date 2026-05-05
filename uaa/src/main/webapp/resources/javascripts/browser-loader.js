/*
 * browser-loader.js
 *
 * Loads the correct CSS and JS files based on browser detection (IE11 vs modern).
 * The asset base path is supplied by the server via the script element's
 * data-asset-base attribute (Thymeleaf-rendered). It is validated against a
 * strict allowlist before use — no user-supplied or URL-derived input is accepted.
 */
(function () {
    /* ------------------------------------------------------------------ */
    /* 1. Resolve asset base from the server-rendered data attribute only  */
    /* ------------------------------------------------------------------ */
    var scripts = document.getElementsByTagName('script');
    var thisScript = scripts[scripts.length - 1];
    var rawBase = thisScript.getAttribute('data-asset-base');

    /* Allowlist: only these server-known paths are permitted.
       Any other value (including empty, null, or injected strings) falls back
       to the safe default, preventing path traversal or external URL injection. */
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
    /* 2. Detect IE11 — purely browser-internal, no user input involved   */
    /* ------------------------------------------------------------------ */
    var isIE11 = !!window.MSInputMethodContext && !!document.documentMode;
    var suffix = isIE11 ? '-ie11' : '';

    /* ------------------------------------------------------------------ */
    /* 3. Load CSS — all filenames are hardcoded, suffix is -ie11 or ''   */
    /* ------------------------------------------------------------------ */
    var cssFiles = [
        assetBase + '/stylesheets/application' + suffix + '.css',
        assetBase + '/stylesheets/predix-styles' + suffix + '.css',
        assetBase + '/stylesheets/predix-card-styles' + suffix + '.css'
    ];

    var head = document.head || document.getElementsByTagName('head')[0];
    for (var i = 0; i < cssFiles.length; i++) {
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = cssFiles[i];
        head.appendChild(link);
    }

    /* ------------------------------------------------------------------ */
    /* 4. Load JS — hardcoded paths, no user input                        */
    /* ------------------------------------------------------------------ */
    var jsFile = isIE11
        ? '/resources/javascripts/last_login_time-ie11.js'
        : '/resources/javascripts/last_login_time.js';

    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.src = jsFile;
    head.appendChild(script);
}());
