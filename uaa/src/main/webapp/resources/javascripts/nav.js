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
    var isOpen = this.classList.toggle('open');
    this.setAttribute('aria-expanded', isOpen);
    dropdownContent.classList.toggle('open');
    
    // Change chevron icon
    chevron.textContent = isOpen ? '▲' : '▼';
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', function(e) {
    if (!dropdownTrigger.contains(e.target) && !dropdownContent.contains(e.target)) {
      dropdownTrigger.classList.remove('open');
      dropdownTrigger.setAttribute('aria-expanded', 'false');
      dropdownContent.classList.remove('open');
      chevron.textContent = '▼';
    }
  });

  // Prevent dropdown from closing when clicking inside it
  dropdownContent.addEventListener('click', function(e) {
    e.stopPropagation();
  });
});