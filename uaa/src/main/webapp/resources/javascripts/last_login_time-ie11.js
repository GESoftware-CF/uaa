document.addEventListener('DOMContentLoaded', function () {
    var element = document.getElementById("last_login_time");
    if (element) {
        var lastLogin = element.getAttribute("last-login-success-time");
        // Use textContent instead of innerHTML to prevent XSS attacks
        document.getElementById("last_login_time").textContent =
            new Date(Number(lastLogin)).toLocaleString();
    }
});