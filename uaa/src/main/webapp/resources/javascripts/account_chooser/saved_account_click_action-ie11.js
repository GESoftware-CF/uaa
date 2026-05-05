document.addEventListener('DOMContentLoaded', function () {
    Array.prototype.forEach.call(document.querySelectorAll("a[data-userId]"), function (savedAccountLink) {
        savedAccountLink.addEventListener('click', function () {
            document.getElementById(savedAccountLink.getAttribute('data-userId')).submit();
        })
    })
});
