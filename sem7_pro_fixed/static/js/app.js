// static/js/app.js
document.addEventListener('DOMContentLoaded', () => {
  // Smooth scroll to flash
  const alerts = document.querySelectorAll('.alert');
  if (alerts.length) alerts[0].scrollIntoView({behavior:'smooth'});
});
