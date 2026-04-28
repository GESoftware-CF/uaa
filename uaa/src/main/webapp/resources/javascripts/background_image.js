fetch('/background_images/presigned-url?key=background_images%2Fuaa%2F8f3a4d67-2fa2-44c8-8c71-bd111b377a31_current_uaa_image.png')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
        if (data && data.presignedUrl) {
            document.documentElement.style.backgroundImage = 'url("' + data.presignedUrl + '")';
        }
    })
    .catch(function () {});
