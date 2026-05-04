document.addEventListener('DOMContentLoaded', function() {
  var dropdownTrigger = document.getElementById('nav-dropdown-button');
  var dropdownContent = document.getElementById('nav-dropdown-content');
  var chevron = dropdownTrigger ? dropdownTrigger.querySelector('.chevron') : null;
  
  if (!dropdownTrigger || !dropdownContent || !chevron) {
    console.error('Dropdown elements not found');
    return;
  }

  // Toggle dropdown on button click
  dropdownTrigger.addEventListener('click', function(e) {
    e.stopPropagation();
    var isOpen = this.className.indexOf('open') === -1;
    if (isOpen) {
      this.className += ' open';
      dropdownContent.className += ' open';
    } else {
      this.className = this.className.replace(/\bopen\b/g, '').trim();
      dropdownContent.className = dropdownContent.className.replace(/\bopen\b/g, '').trim();
    }
    this.setAttribute('aria-expanded', isOpen);
    
    // Change chevron icon
    chevron.textContent = isOpen ? '▲' : '▼';
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', function(e) {
    if (!dropdownTrigger.contains(e.target) && !dropdownContent.contains(e.target)) {
      dropdownTrigger.className = dropdownTrigger.className.replace(/\bopen\b/g, '').trim();
      dropdownTrigger.setAttribute('aria-expanded', 'false');
      dropdownContent.className = dropdownContent.className.replace(/\bopen\b/g, '').trim();
      chevron.textContent = '▼';
    }
  });

  // Prevent dropdown from closing when clicking inside it
  dropdownContent.addEventListener('click', function(e) {
    e.stopPropagation();
  });
});