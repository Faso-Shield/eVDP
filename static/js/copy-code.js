/* Bouton « Copier le code » (page de confirmation d'un signalement). */
(function () {
  "use strict";
  document.querySelectorAll("[data-copy-target]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.getElementById(button.getAttribute("data-copy-target"));
      if (!target || !navigator.clipboard) {
        return;
      }
      navigator.clipboard.writeText(target.textContent.trim()).then(function () {
        button.textContent = "Code copié";
      });
    });
  });
})();
