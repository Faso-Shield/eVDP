/*
 * Formulaire de signalement : l'anonymat et le credit public s'excluent.
 * Cocher l'un decoche l'autre. Confort d'interface uniquement : le serveur
 * refuse de toute facon la combinaison (VulnerabilityReport.clean).
 */
(function () {
  "use strict";
  var anonymous = document.getElementById("id_is_anonymous");
  var credit = document.getElementById("id_wants_credit");
  if (!anonymous || !credit) {
    return;
  }
  function exclusive(changed, other) {
    return function () {
      if (changed.checked) {
        other.checked = false;
      }
    };
  }
  anonymous.addEventListener("change", exclusive(anonymous, credit));
  credit.addEventListener("change", exclusive(credit, anonymous));
  if (anonymous.checked && credit.checked) {
    credit.checked = false;
  }
})();
