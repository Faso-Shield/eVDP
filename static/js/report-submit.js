"use strict";
/* Formulaire de signalement assiste.
 *
 * Tout ce qui suit guide la saisie ; rien ne remplace la validation serveur
 * (VulnerabilityReportForm), qui reste seule juge. Sans JavaScript, le
 * formulaire fonctionne a l'identique.
 *
 * Volontairement absent : un brouillon enregistre dans le navigateur. Le
 * detail d'une vulnerabilite non corrigee resterait en clair sur le poste.
 */
(function () {
  var form = document.getElementById("report-form");
  if (!form) return;

  function byId(id) { return document.getElementById(id); }

  // ------------------------------------------ regles du programme choisi
  // Motifs calcules cote serveur par Program.reporter_rejection, pour ce
  // declarant : le meme texte que le refus qu'il recevrait a l'envoi.
  var rules = {};
  try { rules = JSON.parse(form.dataset.programRules || "{}"); } catch (e) { rules = {}; }
  var programField = byId("id_program");
  var anonymousField = byId("id_is_anonymous");
  var creditField = byId("id_wants_credit");
  var ruleNotice = byId("program-rule-notice");
  var creditHint = byId("wants-credit-hint");

  function refreshRules() {
    var rule = programField ? rules[programField.value] : null;
    var anonymous = anonymousField && anonymousField.checked;
    if (anonymousField) {
      // Un programme qui refuse l'anonymat : la case n'a pas de sens.
      var anonymousRefused = !!(rule && rule.refus_anonyme);
      anonymousField.disabled = anonymousRefused;
      if (anonymousRefused) anonymousField.checked = false;
      anonymous = anonymousField.checked;
    }
    if (ruleNotice) {
      var message = rule ? (anonymous ? rule.refus_anonyme : rule.refus) : "";
      ruleNotice.textContent = message || "";
      ruleNotice.hidden = !message;
    }
    if (creditField) {
      // Le credit public nommerait un declarant qui a choisi l'anonymat.
      creditField.disabled = anonymous;
      if (anonymous) creditField.checked = false;
      if (creditHint) creditHint.hidden = !anonymous;
    }
  }
  if (programField) programField.addEventListener("change", refreshRules);
  if (anonymousField) anonymousField.addEventListener("change", refreshRules);
  refreshRules();

  // ------------------------------------ organisation hors liste seulement
  var orgSelect = byId("id_affected_organization");
  var orgNameField = byId("id_affected_organization_name");
  if (orgSelect && orgNameField) {
    var orgNameWrapper = orgNameField.closest(".form-field");
    var refreshOrgName = function () {
      if (orgNameWrapper) orgNameWrapper.hidden = !!orgSelect.value && !orgNameField.value;
    };
    orgSelect.addEventListener("change", refreshOrgName);
    refreshOrgName();
  }

  // --------------------------------------------- description : compteur
  var MIN_DESCRIPTION = 30;
  var description = byId("id_description");
  var counter = byId("description-counter");
  function refreshCounter() {
    if (!description || !counter) return;
    var length = description.value.trim().length;
    counter.textContent = length + " caractère" + (length > 1 ? "s" : "") +
      (length < MIN_DESCRIPTION ? " — " + MIN_DESCRIPTION + " minimum" : "");
    counter.classList.toggle("counter-ok", length >= MIN_DESCRIPTION);
  }
  if (description) description.addEventListener("input", refreshCounter);
  refreshCounter();

  var templateButton = byId("insert-template");
  if (templateButton && description) {
    templateButton.hidden = false;
    templateButton.addEventListener("click", function () {
      if (description.value.trim() && !window.confirm("Remplacer le texte actuel par le modèle ?")) {
        return;
      }
      description.value =
        "## Résumé\n\nLa vulnérabilité en une ou deux phrases.\n\n" +
        "## Composant concerné\n\nPage, point d'API ou service, et version si connue.\n\n" +
        "## Cause supposée\n\nCe qui rend l'attaque possible.\n";
      refreshCounter();
      description.focus();
    });
  }

  // -------------------------------------- pieces jointes : depot et liste
  var dropzone = byId("dropzone");
  var fileInput = byId("attachments");
  var fileList = byId("file-list");
  var fileWarning = byId("file-limit-warning");
  var maxFiles = parseInt(form.dataset.maxAttachments, 10) || 5;
  if (dropzone && fileInput && fileList && window.DataTransfer) {
    dropzone.hidden = false;
    var files = [];
    var render = function () {
      var transfer = new DataTransfer();
      files.forEach(function (file) { transfer.items.add(file); });
      fileInput.files = transfer.files;
      fileList.textContent = "";
      files.forEach(function (file, index) {
        var item = document.createElement("li");
        item.className = "file-list-item";
        var label = document.createElement("span");
        var size = file.size >= 1048576
          ? (file.size / 1048576).toFixed(1) + " Mo"
          : Math.max(1, Math.round(file.size / 1024)) + " Ko";
        label.textContent = file.name + " (" + size + ")";
        var remove = document.createElement("button");
        remove.type = "button";
        remove.className = "btn btn-sm btn-outline";
        remove.textContent = "Retirer";
        remove.addEventListener("click", function () {
          files.splice(index, 1);
          if (fileWarning) fileWarning.hidden = true;
          render();
        });
        item.appendChild(label);
        item.appendChild(remove);
        fileList.appendChild(item);
      });
    };
    var add = function (incoming) {
      var refused = 0;
      Array.prototype.forEach.call(incoming, function (file) {
        if (files.length < maxFiles) files.push(file); else refused += 1;
      });
      if (fileWarning) {
        fileWarning.hidden = refused === 0;
        fileWarning.textContent = refused
          ? refused + " fichier(s) non ajouté(s) : " + maxFiles + " au maximum par envoi."
          : "";
      }
      render();
    };
    fileInput.addEventListener("change", function () {
      var picked = Array.prototype.slice.call(fileInput.files);
      add(picked);
    });
    dropzone.addEventListener("click", function () { fileInput.click(); });
    dropzone.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInput.click(); }
    });
    ["dragenter", "dragover"].forEach(function (name) {
      dropzone.addEventListener(name, function (event) {
        event.preventDefault();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (name) {
      dropzone.addEventListener(name, function () { dropzone.classList.remove("dragover"); });
    });
    dropzone.addEventListener("drop", function (event) {
      event.preventDefault();
      if (event.dataTransfer) add(event.dataTransfer.files);
    });
  }
})();
