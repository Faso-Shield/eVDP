/**
 * Boutons de workflow : chaque clic ouvre une fenetre de confirmation.
 *
 * Un bouton `[data-open-dialog="<id>"]` ouvre le <dialog> correspondant, qui
 * contient le formulaire de l'action (commentaire et champs exiges par
 * l'etape). `[data-close-dialog]` le referme sans rien envoyer.
 *
 * Purement ergonomique : l'autorisation, les pre-requis et la regle des
 * quatre yeux sont verifies cote serveur (apps.coordination.workflow).
 */
(function () {
  "use strict";

  function init() {
    document.querySelectorAll("[data-open-dialog]").forEach(function (button) {
      button.addEventListener("click", function () {
        var dialog = document.getElementById(button.getAttribute("data-open-dialog"));
        if (dialog && typeof dialog.showModal === "function") {
          dialog.showModal();
        }
      });
    });
    document.querySelectorAll("[data-close-dialog]").forEach(function (button) {
      button.addEventListener("click", function () {
        var dialog = button.closest("dialog");
        if (dialog) {
          dialog.close();
        }
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
