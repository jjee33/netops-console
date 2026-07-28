// Progressive enhancement only. Every page works with this file absent — the
// CSP forbids inline script, so anything here has to be a real file, and that
// makes it worth keeping small enough to read in one sitting.

(function () {
  "use strict";

  // Clicking a detected-subnet chip fills the scan field. Delegated from the
  // document so it keeps working after HTMX swaps part of the page.
  document.addEventListener("click", function (event) {
    var chip = event.target.closest("[data-subnet]");
    if (!chip) {
      return;
    }
    var field = document.getElementById("subnet");
    if (!field) {
      return;
    }
    field.value = chip.dataset.subnet;
    field.focus();
  });
})();
