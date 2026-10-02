"use strict";
/* Chiffrement et dechiffrement PGP dans le navigateur (OpenPGP.js).
 *
 * Signaleur : chiffre ses details sensibles, et s'il le souhaite ses pieces
 * jointes, avec la cle publique nationale, avant l'envoi. Le texte en clair
 * n'a pas d'attribut name : il ne part jamais au serveur.
 *
 * Analyste : dechiffre le bloc du rapport et les pieces .gpg avec SA cle
 * privee, chargee dans la page le temps de l'operation. Elle n'est ni envoyee
 * au serveur, ni conservee (aucun stockage navigateur) : fermer la page
 * l'efface.
 *
 * Gestionnaire de la cle nationale : genere la paire ici (seule la cle
 * publique est envoyee pour publication) et prepare la remise de la cle
 * privee, chiffree par un code de remise aleatoire qui ne part jamais au
 * serveur. Destinataire : saisit ce code, dechiffre la remise ici et
 * enregistre la cle sur son poste.
 */
(function () {
  if (typeof openpgp === "undefined") return;

  function byId(id) { return document.getElementById(id); }

  function show(el, text, isError) {
    if (!el) return;
    el.hidden = false;
    el.textContent = text;
    el.classList.toggle("sla-text-breached", Boolean(isError));
  }

  function download(text, filename) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type: "application/pgp-keys" }));
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 10000);
  }

  async function postForm(url, form) {
    const response = await fetch(url, {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { "X-Requested-With": "XMLHttpRequest" },
    });
    const data = await response.json().catch(function () { return {}; });
    if (!response.ok) throw new Error(data.error || "refus du serveur (" + response.status + ")");
    return data;
  }

  // Code de remise : 24 caracteres sur 32 symboles sans ambiguite (120 bits).
  const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  function newDeliveryCode() {
    const bytes = crypto.getRandomValues(new Uint8Array(24));
    return Array.from(bytes, function (b) { return CODE_ALPHABET[b & 31]; }).join("");
  }

  function groupCode(code) {
    return code.match(/.{1,4}/g).join("-");
  }

  async function nationalKey(url) {
    const response = await fetch(url, { credentials: "same-origin" });
    if (!response.ok) throw new Error("Clé publique nationale indisponible.");
    return openpgp.readKey({ armoredKey: await response.text() });
  }

  // ------------------------------------------------------------ signaleur
  const encryptBox = byId("pgp-encrypt");
  if (encryptBox) {
    encryptBox.hidden = false;
    const keyUrl = encryptBox.dataset.keyUrl;
    const plain = byId("pgp-plaintext");
    const payload = byId("id_pgp_payload");
    const status = byId("pgp-encrypt-status");
    const encryptFiles = byId("pgp-encrypt-files");
    const form = byId("report-form");

    byId("pgp-encrypt-button").addEventListener("click", async function () {
      if (!plain.value.trim()) {
        show(status, "Saisissez d'abord le texte à chiffrer.", true);
        return;
      }
      try {
        const key = await nationalKey(keyUrl);
        const armored = await openpgp.encrypt({
          message: await openpgp.createMessage({ text: plain.value }),
          encryptionKeys: key,
        });
        payload.value = (payload.value.trim() ? payload.value.trim() + "\n\n" : "") + armored;
        plain.value = "";
        show(status, "Texte chiffré et placé dans le bloc PGP ci-dessous. Le texte en clair a été effacé.");
      } catch (error) {
        show(status, "Chiffrement impossible : " + error.message, true);
      }
    });

    // Pieces jointes : chiffrees juste avant l'envoi, en .gpg binaire.
    if (form && encryptFiles) {
      let encrypted = false;
      form.addEventListener("submit", async function (event) {
        const input = byId("attachments");
        if (encrypted || !encryptFiles.checked || !input || !input.files.length) return;
        event.preventDefault();
        try {
          const key = await nationalKey(keyUrl);
          const transfer = new DataTransfer();
          for (const file of Array.from(input.files)) {
            if (/\.(gpg|pgp|asc)$/i.test(file.name)) {
              transfer.items.add(file);
              continue;
            }
            const message = await openpgp.createMessage({
              binary: new Uint8Array(await file.arrayBuffer()),
              filename: file.name,
            });
            const data = await openpgp.encrypt({ message, encryptionKeys: key, format: "binary" });
            transfer.items.add(new File([data], file.name + ".gpg", { type: "application/pgp-encrypted" }));
          }
          input.files = transfer.files;
          encrypted = true;
          form.requestSubmit();
        } catch (error) {
          show(status, "Chiffrement des pièces jointes impossible : " + error.message, true);
        }
      });
    }
  }

  // ------------------------------------------- gestionnaire : generation
  // Cle privee generee sur cette page, gardee en memoire pour une remise.
  let generatedPrivate = null;

  const generateBox = byId("pgp-generate");
  if (generateBox) {
    generateBox.hidden = false;
    const status = byId("pgp-gen-status");
    const result = byId("pgp-generated");
    const saved = byId("pgp-gen-saved");
    const publish = byId("pgp-gen-publish");
    let revocation = null;
    let fingerprint = "";

    byId("pgp-gen-button").addEventListener("click", async function () {
      const passphrase = byId("pgp-gen-passphrase");
      const confirm = byId("pgp-gen-confirm");
      const name = byId("pgp-gen-name").value.trim();
      const email = byId("pgp-gen-email").value.trim();
      if (!name || !email) return show(status, "Renseignez le nom et l'adresse de la clé.", true);
      if (passphrase.value.length < 12) {
        return show(status, "La phrase secrète doit compter 12 caractères au moins.", true);
      }
      if (passphrase.value !== confirm.value) {
        return show(status, "Les deux phrases secrètes diffèrent.", true);
      }
      this.disabled = true;
      show(status, "Génération en cours…");
      try {
        const years = Number(byId("pgp-gen-validity").value);
        const pair = await openpgp.generateKey({
          type: "ecc",
          curve: "curve25519Legacy",
          userIDs: [{ name: name, email: email }],
          passphrase: passphrase.value,
          keyExpirationTime: years * 365 * 24 * 3600,
          format: "armored",
        });
        const key = await openpgp.readKey({ armoredKey: pair.publicKey });
        const expires = await key.getExpirationTime();
        generatedPrivate = pair.privateKey;
        revocation = pair.revocationCertificate;
        fingerprint = key.getFingerprint().toUpperCase();
        passphrase.value = "";
        confirm.value = "";
        byId("pgp-gen-public").value = pair.publicKey;
        byId("pgp-gen-fingerprint").textContent = groupCode(fingerprint).replace(/-/g, " ");
        byId("pgp-gen-expires").textContent =
          expires instanceof Date ? expires.toLocaleDateString("fr-FR") : "Jamais";
        result.hidden = false;
        const hint = byId("pgp-deliver-generated-hint");
        if (hint) hint.hidden = false;
        show(status, "Paire générée dans votre navigateur. Enregistrez la clé privée avant de publier.");
      } catch (error) {
        show(status, "Génération impossible : " + error.message, true);
      } finally {
        this.disabled = false;
      }
    });

    byId("pgp-gen-download-private").addEventListener("click", function () {
      download(generatedPrivate, "evdp-national-" + fingerprint.slice(-16) + "-PRIVEE.asc");
      saved.disabled = false;
    });
    byId("pgp-gen-download-revocation").addEventListener("click", function () {
      download(revocation, "evdp-national-" + fingerprint.slice(-16) + "-revocation.asc");
    });
    saved.addEventListener("change", function () { publish.disabled = !saved.checked; });
    byId("pgp-gen-publish-form").addEventListener("submit", function (event) {
      if (!saved.checked) event.preventDefault();
    });
  }

  // ---------------------------------------------- gestionnaire : remise
  const deliverForm = byId("pgp-deliver");
  if (deliverForm) {
    deliverForm.hidden = false;
    const status = byId("pgp-deliver-status");
    const fileInput = byId("pgp-deliver-file");
    const payload = byId("pgp-deliver-payload");
    const button = byId("pgp-deliver-button");

    deliverForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (!byId("pgp-deliver-recipient").value) return show(status, "Choisissez le destinataire.", true);
      button.disabled = true;
      try {
        let armored = fileInput.files.length ? (await fileInput.files[0].text()).trim() : generatedPrivate;
        if (!armored) throw new Error("chargez le fichier de la clé privée.");
        const key = await openpgp.readPrivateKey({ armoredKey: armored });
        if (key.getFingerprint().toUpperCase() !== deliverForm.dataset.fingerprint) {
          throw new Error("cette clé privée ne correspond pas à la clé nationale publiée.");
        }
        if (key.isDecrypted()) {
          throw new Error("la clé privée doit être protégée par une phrase secrète.");
        }
        const code = newDeliveryCode();
        payload.value = await openpgp.encrypt({
          message: await openpgp.createMessage({ text: armored }),
          passwords: [code],
        });
        armored = null;
        const data = await postForm(deliverForm.action, deliverForm);
        byId("pgp-delivery-recipient").textContent = data.recipient;
        byId("pgp-delivery-expires").textContent = data.expires_at;
        byId("pgp-delivery-code").textContent = groupCode(code);
        byId("pgp-delivery-result").hidden = false;
        fileInput.value = "";
        show(status, "Remise préparée. Le destinataire est prévenu par notification et par email.");
      } catch (error) {
        show(status, "Remise impossible : " + error.message, true);
      } finally {
        payload.value = "";
        button.disabled = false;
      }
    });

    byId("pgp-delivery-copy").addEventListener("click", function () {
      navigator.clipboard.writeText(byId("pgp-delivery-code").textContent).then(
        function () { show(status, "Code copié."); },
        function () { show(status, "Copie impossible : sélectionnez le code à la main.", true); }
      );
    });
  }

  // ------------------------------------------- destinataire : recuperation
  const retrieveForm = byId("pgp-retrieve");
  if (retrieveForm) {
    retrieveForm.hidden = false;
    const status = byId("pgp-retrieve-status");
    const codeInput = byId("pgp-retrieve-code");

    retrieveForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const code = codeInput.value.toUpperCase().replace(/[^A-Z0-9]/g, "");
      if (code.length !== 24) return show(status, "Le code compte 24 caractères.", true);
      const submit = retrieveForm.querySelector("button[type=submit]");
      submit.disabled = true;
      try {
        const data = await postForm(retrieveForm.dataset.fetchUrl, retrieveForm);
        let armored;
        try {
          const message = await openpgp.readMessage({ armoredMessage: data.payload });
          armored = (await openpgp.decrypt({ message: message, passwords: [code] })).data;
        } catch (error) {
          const left = data.remaining > 0 ? " Il reste " + data.remaining + " essai(s)." : " Plus aucun essai.";
          throw new Error("code incorrect." + left);
        }
        const key = await openpgp.readPrivateKey({ armoredKey: armored });
        if (key.getFingerprint().toUpperCase() !== data.fingerprint) {
          throw new Error("la clé reçue ne correspond pas à l'empreinte annoncée.");
        }
        download(armored, "evdp-national-" + data.fingerprint.slice(-16) + "-PRIVEE.asc");
        await postForm(retrieveForm.dataset.confirmUrl, retrieveForm);
        codeInput.value = "";
        retrieveForm.querySelector(".form-field").remove();
        submit.closest(".btn-row").remove();
        const state = byId("pgp-retrieve-state");
        if (state) state.textContent = "Récupérée";
        show(status, "Clé enregistrée sur votre poste et effacée du serveur. Conservez le fichier en lieu sûr.");
      } catch (error) {
        show(status, "Récupération impossible : " + error.message, true);
        submit.disabled = false;
      }
    });
  }

  // ------------------------------------------------------------- analyste
  const decryptBox = byId("pgp-decrypt");
  if (decryptBox) {
    decryptBox.hidden = false;
    const keyFile = byId("pgp-private-file");
    const keyText = byId("pgp-private-text");
    const passphrase = byId("pgp-passphrase");
    const status = byId("pgp-decrypt-status");
    const output = byId("pgp-plain-output");
    let privateKey = null;

    async function loadKey() {
      if (privateKey) return privateKey;
      let armored = keyText.value.trim();
      if (!armored && keyFile.files.length) armored = (await keyFile.files[0].text()).trim();
      if (!armored) throw new Error("Chargez votre clé privée.");
      let key = await openpgp.readPrivateKey({ armoredKey: armored });
      if (!key.isDecrypted()) {
        key = await openpgp.decryptKey({ privateKey: key, passphrase: passphrase.value });
      }
      privateKey = key;
      keyText.value = "";
      passphrase.value = "";
      keyFile.value = "";
      return key;
    }

    byId("pgp-forget").addEventListener("click", function () {
      privateKey = null;
      output.hidden = true;
      output.textContent = "";
      show(status, "Clé oubliée par la page.");
    });

    const blockButton = byId("pgp-decrypt-block");
    if (blockButton) {
      blockButton.addEventListener("click", async function () {
        try {
          const key = await loadKey();
          const message = await openpgp.readMessage({ armoredMessage: byId("pgp-armored").textContent });
          const { data } = await openpgp.decrypt({ message, decryptionKeys: key });
          output.hidden = false;
          output.textContent = data;
          show(status, "Bloc déchiffré dans votre navigateur.");
        } catch (error) {
          show(status, "Déchiffrement impossible : " + error.message, true);
        }
      });
    }

    document.querySelectorAll("[data-pgp-attachment]").forEach(function (button) {
      button.hidden = false;
      button.addEventListener("click", async function () {
        try {
          const key = await loadKey();
          const response = await fetch(button.dataset.pgpAttachment, { credentials: "same-origin" });
          if (!response.ok) throw new Error("téléchargement refusé (" + response.status + ")");
          const bytes = new Uint8Array(await response.arrayBuffer());
          const message = await openpgp.readMessage({ binaryMessage: bytes })
            .catch(() => openpgp.readMessage({ armoredMessage: new TextDecoder().decode(bytes) }));
          const { data } = await openpgp.decrypt({ message, decryptionKeys: key, format: "binary" });
          const link = document.createElement("a");
          link.href = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
          link.download = (button.dataset.filename || "piece").replace(/\.(gpg|pgp|asc)$/i, "");
          document.body.appendChild(link);
          link.click();
          link.remove();
          setTimeout(function () { URL.revokeObjectURL(link.href); }, 10000);
          show(status, "Pièce jointe déchiffrée dans votre navigateur.");
        } catch (error) {
          show(status, "Déchiffrement impossible : " + error.message, true);
        }
      });
    });
  }
})();
