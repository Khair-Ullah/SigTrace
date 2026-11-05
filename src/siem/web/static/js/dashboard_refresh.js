/* Auto-refresh dashboard stats/tables via lightweight polling */
(function(){
  "use strict";
  // Only run on dashboard page (has cards with ids or known structure)
  if (!document.querySelector('a[href*="dashboard.index"]')) return;
  // Try to detect dashboard by heading or url
  var path = window.location.pathname;
  if (path.indexOf('/dashboard') === -1 && path !== '/' ) return;

  function refresh(){
    fetch('/dashboard/api/summary', {credentials:'same-origin'})
      .then(function(r){return r.json();})
      .catch(function(){});
  }

  // If no API exists, skip silently
  setInterval(refresh, 10000);
})();
