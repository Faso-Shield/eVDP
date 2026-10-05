"use strict";
/* Formulaire de programme : un Bug Bounty refuse toujours l'anonymat
 * (Program.clean le garantit cote serveur). La case est desactivee et
 * decochee des que ce type est choisi, pour que l'ecran dise la regle au
 * lieu de la laisser decouvrir a l'enregistrement. */
(function () {
  var typeField = document.getElementById("id_program_type");
  var anonymousField = document.getElementById("id_allows_anonymous_reports");
  var hint = document.getElementById("bounty-hint");
  if (!typeField) return;

  function refresh() {
    var bounty = typeField.value === "BUG_BOUNTY";
    if (hint) hint.hidden = !bounty;
    if (anonymousField) {
      anonymousField.disabled = bounty;
      if (bounty) anonymousField.checked = false;
    }
  }
  typeField.addEventListener("change", refresh);
  refresh();
})();
