"use strict";
/* Transforme tout <select class="ts-select"> en champ avec recherche au fil
 * de la frappe (Tom Select). L'element <select> d'origine reste dans le DOM
 * et continue de recevoir sa valeur + ses evenements "change" normalement :
 * le reste du code (report-submit.js, etc.) n'a rien a savoir de Tom Select. */
(function () {
  function enhance(select) {
    if (select.tomselect) return;
    new TomSelect(select, {
      allowEmptyOption: !select.required,
      maxOptions: null,
      create: false,
      placeholder: select.dataset.placeholder || "Rechercher…",
      render: {
        no_results: function () {
          return '<div class="no-results">Aucun résultat.</div>';
        },
      },
    });
  }

  document.querySelectorAll("select.ts-select").forEach(enhance);
})();
