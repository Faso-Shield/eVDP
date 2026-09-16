"""Support PGP.

Contraintes de securite :
  - la plateforme ne stocke JAMAIS de cle privee ;
  - seules des cles publiques armurees sont conservees ;
  - eVDP ne dechiffre et ne verifie JAMAIS de signature PGP cote serveur :
    seule la forme des blocs (en-tete/pied de page) est controlee. La
    verification cryptographique reelle appartient exclusivement a la
    personne qui detient la cle privee correspondante, hors ligne.
"""

import re

from django.conf import settings

PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PUBLIC_KEY_FOOTER = "-----END PGP PUBLIC KEY BLOCK-----"
PRIVATE_KEY_MARKERS = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)
MESSAGE_HEADER = "-----BEGIN PGP MESSAGE-----"
MESSAGE_FOOTER = "-----END PGP MESSAGE-----"


class PGPError(ValueError):
    pass


def contains_private_key(blob):
    return any(marker in (blob or "") for marker in PRIVATE_KEY_MARKERS)


def validate_public_key(blob):
    """Verifie la forme d'une cle publique armuree.

    Leve PGPError si le bloc est invalide ou s'il contient une cle privee.
    """
    blob = (blob or "").strip()
    if not blob:
        return ""
    if contains_private_key(blob):
        raise PGPError(
            "Un bloc de cle privee a ete detecte. eVDP ne stocke jamais de "
            "cle privee : ne transmettez que votre cle publique."
        )
    if PUBLIC_KEY_HEADER not in blob or PUBLIC_KEY_FOOTER not in blob:
        raise PGPError("Bloc de cle publique PGP invalide (en-tete ou pied manquant).")
    if len(blob) > 65536:
        raise PGPError("Bloc de cle publique PGP trop volumineux.")
    return blob


def is_encrypted_blob(blob):
    """Verifie la FORME d'un bloc chiffre PGP (en-tete ET pied de page).

    Ceci n'est jamais un dechiffrement ni une preuve que le contenu est
    reellement exploitable : seule la personne qui detient la cle privee
    peut le savoir, hors ligne. Sans le controle du pied de page, un bloc
    tronque ou corrompu (copier-coller incomplet) passait silencieusement,
    et le CSIRT ne le decouvrait qu'en tentant, bien plus tard, un
    dechiffrement voue a l'echec.
    """
    blob = blob or ""
    return MESSAGE_HEADER in blob and MESSAGE_FOOTER in blob


def fingerprint_hint(blob):
    """Extrait une empreinte si elle est presente en commentaire du bloc."""
    match = re.search(r"Comment:\s*([0-9A-Fa-f\s]{40,})", blob or "")
    if match:
        return re.sub(r"\s+", "", match.group(1)).upper()[:40]
    return ""


def national_public_key():
    """Cle publique nationale publiee (telechargeable sur le site).

    La variable d'environnement PGP_PUBLIC_KEY stocke la cle sur une seule
    ligne (sauts de ligne echappes en \\n), car docker-compose ne supporte
    pas les valeurs multi-lignes dans sa substitution ${VAR}. On les
    reconvertit ici en vrais sauts de ligne : un bloc PGP arme sans retours
    a la ligne reels n'est pas valide pour les outils GPG standards.
    """
    key = (settings.EVDP.get("PGP_PUBLIC_KEY") or "").strip()
    return key.replace("\\n", "\n")


def national_fingerprint():
    return (settings.EVDP.get("PGP_FINGERPRINT") or "").strip()
