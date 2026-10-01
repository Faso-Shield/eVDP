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
