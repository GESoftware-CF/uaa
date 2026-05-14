/*
 * browser-loader.js
 *
 * Loads the correct CSS and JS files based on browser detection (legacy vs modern).
 * "Legacy" covers IE11 and EdgeHTML-era engines (e.g. UWP System Auth Broker using
 * Chakra JS), both of which lack NodeList.prototype.forEach and other ES6+ APIs.
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
    var rawPredixBase = thisScript.getAttribute('data-predix-base');

    /* Allowlist: only these server-known paths are permitted.
       Any other value (including empty, null, or injected strings) falls back
       to the safe default, preventing path traversal or external URL injection. */
    var ALLOWED_BASES = [
        '/resources/oss',
        '/resources/predix'
    ];
    var assetBase = '/resources/predix'; /* safe default — predix has IE11 CSS variants */
    for (var a = 0; a < ALLOWED_BASES.length; a++) {
        if (rawBase === ALLOWED_BASES[a]) {
            assetBase = ALLOWED_BASES[a];
            break;
        }
    }
    var predixBase = '/resources/predix'; /* safe default */
    for (var p = 0; p < ALLOWED_BASES.length; p++) {
        if (rawPredixBase === ALLOWED_BASES[p]) {
            predixBase = ALLOWED_BASES[p];
            break;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 2. Detect legacy browsers — purely browser-internal, no user input */
    /*                                                                    */
    /* isIE11: true only for Internet Explorer 11.                        */
    /* isLegacyBrowser: true for IE11 *and* EdgeHTML-era engines such as  */
    /*   the UWP System Auth Broker (Chakra JS). EdgeHTML does not set    */
    /*   document.documentMode, so the IE11 check alone misses it.       */
    /*   The reliable cross-check is the absence of NodeList.forEach,     */
    /*   which all modern engines (V8, SpiderMonkey, JavaScriptCore)      */
    /*   support but Chakra JS / EdgeHTML do not.                         */
    /* ------------------------------------------------------------------ */
    var isIE11 = !!window.MSInputMethodContext && !!document.documentMode;
    var isLegacyBrowser = isIE11 || !NodeList.prototype.forEach;

    /* ------------------------------------------------------------------ */
    /* 3. Swap CSS to -ie11 variants for legacy browsers.                 */
    /*                                                                    */
    /* The three CSS <link> elements are already in <head> as static,     */
    /* render-blocking tags (ids: css-app, css-styles, css-card). The     */
    /* browser blocks body rendering until they load, so there is no      */
    /* flash of unstyled content (FOUC).                                  */
    /*                                                                    */
    /* For legacy browsers we swap the href to the -ie11 file here,       */
    /* synchronously, before <body> is parsed. The browser then loads the */
    /* correct file and renders the body once only.                       */
    /* application.css has no -ie11 variant so it is left unchanged.      */
    /* ------------------------------------------------------------------ */
    if (isLegacyBrowser) {
        var cssStyles = document.getElementById('css-styles');
        var cssCard   = document.getElementById('css-card');
        if (cssStyles) { cssStyles.href = predixBase + '/stylesheets/predix-styles-ie11.css'; }
        if (cssCard)   { cssCard.href   = predixBase + '/stylesheets/predix-card-styles-ie11.css'; }
    }

    /* ------------------------------------------------------------------ */
    /* 4. Populate last-login-time span                                   */
    /* Inlined here (not loaded as a separate async script) so the        */
    /* DOMContentLoaded listener is registered synchronously, avoiding a  */
    /* race condition where Selenium checks the span before the async     */
    /* script has loaded and populated its textContent.                   */
    /* ------------------------------------------------------------------ */
    function initLastLoginTime() {
        var element = document.getElementById('last_login_time');
        if (element) {
            var lastLogin = element.getAttribute('last-login-success-time');
            /* Use textContent instead of innerHTML to prevent XSS attacks */
            element.textContent = new Date(Number(lastLogin)).toLocaleString();
        }
    }

    /* ------------------------------------------------------------------ */
    /* 5. IE11: set .predix-card height dynamically based on content      */
    /* IE11 cannot resolve flex:1 children without an explicit height on  */
    /* the flex container. We measure the natural content height after    */
    /* layout and apply it so the card fits its content exactly rather    */
    /* than using a hardcoded magic number in the CSS.                    */
    /* Re-runs on window resize so all media query breakpoints are        */
    /* handled correctly.                                                 */
    /* ------------------------------------------------------------------ */
    function fixIE11CardHeight() {
        if (!isLegacyBrowser) { return; }
        var cards = document.querySelectorAll('.predix-card');
        for (var c = 0; c < cards.length; c++) {
            var card = cards[c];
            /* Remove any fixed height/min-height so we can read natural scrollHeight */
            card.style.height = 'auto';
            card.style.minHeight = 'auto';
            var naturalHeight = card.scrollHeight;
            /* Add 40px breathing room for padding/borders */
            card.style.height = (naturalHeight + 40) + 'px';
        }
    }

    /* Debounce resize handler to avoid thrashing layout on every pixel change */
    var resizeTimer;
    function onResize() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(fixIE11CardHeight, 100);
    }

    /* browser-loader.js runs in <head> before the footer is parsed,
       so readyState will be 'loading' — register the listener normally. */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            initLastLoginTime();
            fixIE11CardHeight();
            if (isLegacyBrowser) { window.addEventListener('resize', onResize); }
        });
    } else {
        initLastLoginTime();
        fixIE11CardHeight();
        if (isLegacyBrowser) { window.addEventListener('resize', onResize); }
    }
}());
