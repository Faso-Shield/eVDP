(function () {
  "use strict";

  var form = document.getElementById("report-form");
  if (!form) return;

  var programRules = {};
  try {
    programRules = JSON.parse(form.dataset.anonymityRules || "{}");
  } catch (e) { /* regles illisibles : on se rabat sur un objet vide */ }

  var authenticated = form.dataset.authenticated === "1";
  var emailVerified = form.dataset.emailVerified === "1";
  var mfaEnabled = form.dataset.mfaEnabled === "1";
  var programField = document.getElementById("id_program");
  var anonymousField = document.getElementById("id_is_anonymous");
  var warning = document.getElementById("anonymous-bounty-warning");
  var VDP_WARNING_TEXT = warning ? warning.textContent : "";
  var BOUNTY_ACCOUNT_TEXT =
    "Ce programme offre des récompenses : un compte est obligatoire pour " +
    "soumettre (attribution de récompense, historique, lutte anti-fraude). " +
    "Un simple email de contact ne suffit pas. Créez un compte ou connectez-vous.";
  var BOUNTY_LOGGED_IN_TEXT =
    "Ce programme offre des récompenses : le signalement anonyme est désactivé.";
  var BOUNTY_UNVERIFIED_TEXT =
    "Ce programme offre des récompenses : votre adresse email doit être " +
    "vérifiée avant de pouvoir soumettre (pour rester joignable au moment " +
    "d'une récompense). Vérifiez-la depuis votre profil.";
  var BOUNTY_NO_MFA_TEXT =
    "Ce programme offre des récompenses : la double authentification doit " +
    "être activée avant de pouvoir soumettre (votre compte pourrait " +
    "recevoir une récompense, il doit être mieux protégé). Activez-la " +
    "depuis votre profil.";
  var accountNoticeText = document.getElementById("account-notice-text");
  var DEFAULT_ACCOUNT_NOTICE = accountNoticeText ? accountNoticeText.textContent : "";
  var BOUNTY_ACCOUNT_NOTICE =
    "Vous n'êtes pas connecté. Ce programme Bug Bounty exige un compte : " +
    "l'anonymat et un simple email de contact ne suffisent pas pour être " +
    "récompensé.";
  if (programField && anonymousField && warning) {
    var refreshAnonymity = function () {
      var rule = programRules[programField.value];
      var anonymousAllowed = !rule || rule.anonymous_allowed;
      anonymousField.disabled = !anonymousAllowed;
      if (rule && rule.is_bounty) {
        warning.hidden = false;
        if (!authenticated) {
          warning.textContent = BOUNTY_ACCOUNT_TEXT;
        } else if (!emailVerified) {
          warning.textContent = BOUNTY_UNVERIFIED_TEXT;
        } else if (!mfaEnabled) {
          warning.textContent = BOUNTY_NO_MFA_TEXT;
        } else {
          warning.textContent = BOUNTY_LOGGED_IN_TEXT;
        }
      } else {
        warning.hidden = anonymousAllowed;
        warning.textContent = VDP_WARNING_TEXT;
      }
      if (accountNoticeText && !authenticated) {
        accountNoticeText.textContent =
          rule && rule.is_bounty ? BOUNTY_ACCOUNT_NOTICE : DEFAULT_ACCOUNT_NOTICE;
      }
      if (!anonymousAllowed) anonymousField.checked = false;
    };
    programField.addEventListener("change", refreshAnonymity);
    refreshAnonymity();
  }

  // ------------------------------ credit public : sans effet en mode anonyme
  var wantsCreditField = document.getElementById("id_wants_credit");
  var wantsCreditHint = document.getElementById("wants-credit-hint");
  if (anonymousField && wantsCreditField && wantsCreditHint) {
    var refreshCredit = function () {
      var anonymous = anonymousField.checked;
      wantsCreditField.disabled = anonymous;
      wantsCreditHint.hidden = !anonymous;
      if (anonymous) wantsCreditField.checked = false;
    };
    anonymousField.addEventListener("change", refreshCredit);
    refreshCredit();
  }

  // ---------------------------------------------------- organisation : n'afficher
  // le champ texte libre que si aucune organisation n'est choisie dans la liste.
  var orgSelect = document.getElementById("id_affected_organization");
  var orgNameField = document.getElementById("org-name-field");
  if (orgSelect && orgNameField) {
    var refreshOrgName = function () {
      orgNameField.hidden = !!orgSelect.value;
    };
    orgSelect.addEventListener("change", refreshOrgName);
    refreshOrgName();
  }

  // --------------------------------------------------------------- compteur
  var description = document.getElementById("id_description");
  var counter = document.getElementById("description-counter");
  if (description && counter) {
    var refreshCounter = function () {
      var length = description.value.length;
      var ok = length >= 30;
      counter.textContent = length + " caractère" + (length > 1 ? "s" : "") + (ok ? "" : " (30 minimum)");
      counter.classList.toggle("ok", ok);
    };
    description.addEventListener("input", refreshCounter);
    refreshCounter();
  }

  var templateButton = document.getElementById("insert-template");
  if (templateButton && description) {
    templateButton.addEventListener("click", function () {
      if (description.value.trim() && !window.confirm("Remplacer le contenu actuel par le modèle ?")) {
        return;
      }
      description.value =
        "## Résumé\n\nDécrivez la vulnérabilité en une ou deux phrases.\n\n" +
        "## Étapes de reproduction\n1. \n2. \n3. \n\n" +
        "## Impact\n\nQue peut faire un attaquant en exploitant cette faille ?\n";
      description.dispatchEvent(new Event("input"));
      description.focus();
    });
  }

  // ------------------------------ suggestion PGP pour severite critique
  // Non bloquant : un simple rappel visible, jamais une condition d'envoi.
  var severityField = document.getElementById("id_reported_severity");
  var pgpField = document.getElementById("id_pgp_payload");
  var pgpHint = document.getElementById("pgp-severity-hint");
  if (severityField && pgpField && pgpHint) {
    var refreshPgpHint = function () {
      var critical = severityField.value === "CRITICAL";
      var empty = !pgpField.value.trim();
      pgpHint.hidden = !(critical && empty);
    };
    severityField.addEventListener("change", refreshPgpHint);
    pgpField.addEventListener("input", refreshPgpHint);
    refreshPgpHint();
  }

  // ------------------------------------------------------- calculateur CVSS
  var METRICS = [
    ["AV", "Vecteur d'attaque", [["N", "Réseau"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physique"]]],
    ["AC", "Complexité d'attaque", [["L", "Faible"], ["H", "Élevée"]]],
    ["PR", "Privilèges requis", [["N", "Aucun"], ["L", "Faibles"], ["H", "Élevés"]]],
    ["UI", "Interaction utilisateur", [["N", "Aucune"], ["R", "Requise"]]],
    ["S", "Portée", [["U", "Inchangée"], ["C", "Modifiée"]]],
    ["C", "Confidentialité", [["N", "Aucune"], ["L", "Faible"], ["H", "Élevée"]]],
    ["I", "Intégrité", [["N", "Aucune"], ["L", "Faible"], ["H", "Élevée"]]],
    ["A", "Disponibilité", [["N", "Aucune"], ["L", "Faible"], ["H", "Élevée"]]]
  ];
  var cvssManualInput = document.getElementById("id_cvss_vector");
  var cvssMetricsContainer = document.getElementById("cvss-metrics");
  var cvssReadout = document.getElementById("cvss-readout");
  var cvssCalculator = document.getElementById("cvss-calculator");
  var cvssManualBlock = document.getElementById("cvss-manual");
  var useManualLink = document.getElementById("cvss-use-manual");
  var useCalculatorLink = document.getElementById("cvss-use-calculator");

  if (cvssManualInput && cvssMetricsContainer && cvssReadout) {
    var selection = {};

    var buildVector = function () {
      var codes = METRICS.map(function (m) { return m[0]; });
      if (codes.every(function (code) { return selection[code]; })) {
        var vector = "CVSS:3.1/" + codes.map(function (code) { return code + ":" + selection[code]; }).join("/");
        cvssManualInput.value = vector;
        cvssReadout.textContent = vector;
      } else {
        cvssReadout.textContent = "Vecteur incomplet — choisissez une option par ligne.";
      }
    };

    METRICS.forEach(function (metric) {
      var code = metric[0], label = metric[1], options = metric[2];
      var wrapper = document.createElement("div");
      wrapper.className = "cvss-metric";
      var title = document.createElement("div");
      title.className = "cvss-metric-label";
      title.textContent = label;
      wrapper.appendChild(title);
      var optionsWrap = document.createElement("div");
      optionsWrap.className = "cvss-options";
      options.forEach(function (opt) {
        var value = opt[0], optLabel = opt[1];
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cvss-option";
        btn.textContent = optLabel + " (" + value + ")";
        btn.addEventListener("click", function () {
          selection[code] = value;
          Array.prototype.forEach.call(optionsWrap.children, function (sibling) {
            sibling.classList.remove("selected");
          });
          btn.classList.add("selected");
          buildVector();
        });
        optionsWrap.appendChild(btn);
      });
      wrapper.appendChild(optionsWrap);
      cvssMetricsContainer.appendChild(wrapper);
    });

    if (useManualLink && useCalculatorLink && cvssCalculator && cvssManualBlock) {
      useManualLink.addEventListener("click", function (event) {
        event.preventDefault();
        cvssCalculator.hidden = true;
        cvssManualBlock.hidden = false;
      });
      useCalculatorLink.addEventListener("click", function (event) {
        event.preventDefault();
        cvssManualBlock.hidden = true;
        cvssCalculator.hidden = false;
        buildVector();
      });
    }
  }

  // -------------------------------------------------- glisser-deposer fichiers
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("attachments");
  var fileList = document.getElementById("file-list");
  var fileLimitWarning = document.getElementById("file-limit-warning");
  var MAX_ATTACHMENTS = parseInt(form.dataset.maxAttachments, 10) || 5;
  if (dropzone && fileInput && fileList && window.DataTransfer) {
    var files = [];

    var refreshFileList = function () {
      fileList.innerHTML = "";
      files.forEach(function (file, index) {
        var item = document.createElement("div");
        item.className = "file-list-item";
        var sizeKb = Math.round(file.size / 1024);
        var label = document.createElement("span");
        label.textContent = file.name + " (" + sizeKb + " Ko)";
        var remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "Retirer";
        remove.addEventListener("click", function () {
          files.splice(index, 1);
          syncInput();
        });
        item.appendChild(label);
        item.appendChild(remove);
        fileList.appendChild(item);
      });
    };

    var syncInput = function () {
      var transfer = new DataTransfer();
      files.slice(0, MAX_ATTACHMENTS).forEach(function (file) { transfer.items.add(file); });
      fileInput.files = transfer.files;
      refreshFileList();
    };

    var addFiles = function (newFiles) {
      var rejected = 0;
      Array.prototype.forEach.call(newFiles, function (file) {
        if (files.length < MAX_ATTACHMENTS) {
          files.push(file);
        } else {
          rejected += 1;
        }
      });
      if (fileLimitWarning) {
        if (rejected > 0) {
          fileLimitWarning.hidden = false;
          fileLimitWarning.textContent = rejected + " fichier" + (rejected > 1 ? "s" : "") +
            " non ajouté" + (rejected > 1 ? "s" : "") + " : maximum " + MAX_ATTACHMENTS +
            " par envoi. Retirez-en un pour en ajouter un autre.";
        } else {
          fileLimitWarning.hidden = true;
        }
      }
      syncInput();
    };

    dropzone.addEventListener("click", function () { fileInput.click(); });
    fileInput.addEventListener("click", function (event) { event.stopPropagation(); });
    fileInput.addEventListener("change", function () { addFiles(fileInput.files); });
    ["dragover", "dragenter"].forEach(function (evt) {
      dropzone.addEventListener(evt, function (event) {
        event.preventDefault();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(function (evt) {
      dropzone.addEventListener(evt, function () { dropzone.classList.remove("dragover"); });
    });
    dropzone.addEventListener("drop", function (event) {
      event.preventDefault();
      if (event.dataTransfer && event.dataTransfer.files) addFiles(event.dataTransfer.files);
    });
  }

  // ------------------------------------------------------- brouillon local
  var DRAFT_KEY = "evdp-report-draft";
  var DRAFT_FIELDS = ["title", "product", "target_url", "affected_organization_name",
    "steps_to_reproduce", "impact", "affected_version", "fixed_version",
    "environment", "external_reference", "recommendations"];
  if (window.localStorage) {
    try {
      var saved = JSON.parse(window.localStorage.getItem(DRAFT_KEY) || "{}");
      DRAFT_FIELDS.concat(["description"]).forEach(function (name) {
        var field = form.elements[name];
        if (field && saved[name] && !field.value) field.value = saved[name];
      });
      if (description) refreshCounter();
    } catch (e) { /* brouillon illisible : on l'ignore silencieusement */ }

    var saveDraft = function () {
      var data = {};
      DRAFT_FIELDS.concat(["description"]).forEach(function (name) {
        var field = form.elements[name];
        if (field) data[name] = field.value;
      });
      try { window.localStorage.setItem(DRAFT_KEY, JSON.stringify(data)); } catch (e) { /* stockage plein ou indisponible */ }
    };
    form.addEventListener("input", saveDraft);
    form.addEventListener("submit", function () {
      try { window.localStorage.removeItem(DRAFT_KEY); } catch (e) { /* rien a faire */ }
    });
  }
})();
