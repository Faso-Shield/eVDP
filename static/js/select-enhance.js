"use strict";
/* Recherche au fil de la frappe sur les listes longues (Tom Select) : tout
 * <select class="ts-select"> est enrichi. Le <select> d'origine reste dans le
 * DOM, recoit sa valeur et ses evenements "change" : le formulaire, sa
 * validation serveur et les autres scripts n'en savent rien. Sans
 * JavaScript, la liste native reste pleinement utilisable. */
(function () {
  if (typeof TomSelect === "undefined") return;
  document.querySelectorAll("select.ts-select").forEach(function (select) {
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
  });
})();
