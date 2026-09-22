/**
 * Portefeuille de versement : un formulaire par type de moyen de paiement.
 *
 * Chaque bloc de champs specifiques a un type porte un attribut
 * `data-method-group` egal a la valeur de PayoutMethodType (BANK_TRANSFER,
 * MOBILE_MONEY, CRYPTO, OTHER). Ce script n'affiche que le groupe
 * correspondant au type actuellement selectionne dans la liste
 * `[name="method_type"]` du meme formulaire.
 *
 * Purement cosmetique : le controle qui compte reste cote serveur
 * (PayoutMethodForm.clean(), voir apps/researchers/forms.py), qui exige et
 * conserve uniquement les champs du type choisi meme sans JavaScript.
 */
(function () {
  "use strict";

  function syncMethodGroups(form) {
    var select = form.querySelector('[name="method_type"]');
    if (!select) {
      return;
    }
    var groups = form.querySelectorAll("[data-method-group]");
    groups.forEach(function (group) {
      group.hidden = group.getAttribute("data-method-group") !== select.value;
    });
  }

  function init() {
    document.querySelectorAll(".method-form").forEach(function (form) {
      var select = form.querySelector('[name="method_type"]');
      if (!select) {
        return;
      }
      syncMethodGroups(form);
      select.addEventListener("change", function () {
        syncMethodGroups(form);
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
