"""Support PGP.

Contraintes de securite :
  - la plateforme ne stocke JAMAIS de cle privee ;
  - seules des cles publiques armurees sont conservees ;
  - la verification cryptographique reelle est deleguee a un backend
    optionnel (python-gnupg), afin de pouvoir basculer plus tard vers un HSM
    sans modifier le code appelant.
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
SIGNED_MESSAGE_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----"


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
    return MESSAGE_HEADER in (blob or "")


def is_signed_blob(blob):
    return SIGNED_MESSAGE_HEADER in (blob or "")


def fingerprint_hint(blob):
    """Extrait une empreinte si elle est presente en commentaire du bloc."""
    match = re.search(r"Comment:\s*([0-9A-Fa-f\s]{40,})", blob or "")
    if match:
        return re.sub(r"\s+", "", match.group(1)).upper()[:40]
    return ""


def national_public_key():
    """Cle publique nationale publiee (telechargeable sur le site)."""
    return (settings.EVDP.get("PGP_PUBLIC_KEY") or "").strip()


def national_fingerprint():
    return (settings.EVDP.get("PGP_FINGERPRINT") or "").strip()


def verify_signature(payload, signature=None, public_key=None):
    """Verifie une signature PGP si un backend gnupg est disponible.

    Retourne un dict {verified, backend, detail}. En l'absence de backend
    l'appelant doit considerer le contenu comme NON verifie.
    TODO : brancher un HSM ou un service de signature dedie.
    """
    try:
        import gnupg  # type: ignore
    except ImportError:
        return {
            "verified": False,
            "backend": None,
            "detail": "Backend gnupg indisponible : verification non effectuee.",
        }

    try:  # pragma: no cover - depend de l'environnement
        gpg = gnupg.GPG()
        if public_key:
            gpg.import_keys(public_key)
        result = (
            gpg.verify_data(signature, payload.encode()) if signature else gpg.verify(payload)
        )
        return {
            "verified": bool(result),
            "backend": "gnupg",
            "detail": getattr(result, "status", "") or "",
        }
    except Exception as exc:  # pragma: no cover
        return {"verified": False, "backend": "gnupg", "detail": str(exc)}
