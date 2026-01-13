/**
 * Toast notification functionality
 * Handles toast notifications and providing accessibility features
 * Toasts will remain visible until manually closed by the user
 */
(function() {
  document.addEventListener('DOMContentLoaded', function() {
    // Find all toast notifications
    const toasts = document.querySelectorAll('.toast');
    
    // Process each toast
    toasts.forEach(function(toast) {
      // Set up close button behavior
      const closeButton = toast.querySelector('.toast__close');
      if (closeButton) {
        closeButton.addEventListener('click', function() {
          // Add fade out effect
          toast.style.opacity = '0';
          toast.style.transition = 'opacity 0.5s ease';
          
          // Remove from DOM after animation completes
          setTimeout(function() {
            if (toast.parentNode) {
              toast.style.display = 'none';
            }
          }, 500);
        });
      }
    });
  });
})();