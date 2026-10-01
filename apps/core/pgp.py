"""Support PGP.

Contraintes de securite :
  - la plateforme ne stocke JAMAIS de cle privee ;
  - seules des cles publiques armurees sont conservees ;
  - eVDP ne dechiffre JAMAIS cote serveur : chiffrement et dechiffrement se
    font dans le navigateur (static/js/pgp.js, OpenPGP.js), la cle privee de
    l'analyste ne quitte pas son poste.

Cote serveur, une cle publique est analysee (inspect_public_key) : paquets
OpenPGP (RFC 4880 et 9580) lus pour calculer l'empreinte, la date de
creation et la date d'expiration, sans aucune operation cryptographique.
"""

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.utils import timezone

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
            "Un bloc de clé privée a été détecté. eVDP ne stocke jamais de "
            "clé privée : ne transmettez que votre clé publique."
        )
    if PUBLIC_KEY_HEADER not in blob or PUBLIC_KEY_FOOTER not in blob:
        raise PGPError("Bloc de clé publique PGP invalide (en-tête ou pied manquant).")
    if len(blob) > 65536:
        raise PGPError("Bloc de clé publique PGP trop volumineux.")
    info = inspect_public_key(blob)
    if info.is_expired:
        raise PGPError(
            f"Cette clé a expiré le {timezone.localtime(info.expires_at):%d/%m/%Y} : "
            "publiez une clé valide."
        )
    return blob


# ---------------------------------------------------------------------------
# Analyse d'une cle publique (sans cryptographie)
# ---------------------------------------------------------------------------
#: Types de paquets OpenPGP utiles ici.
_TAG_SIGNATURE, _TAG_SECRET_KEY, _TAG_PUBLIC_KEY = 2, 5, 6
_TAG_SECRET_SUBKEY, _TAG_USER_ID = 7, 13
#: Auto-signatures portant les preferences de la cle : certifications d'un
#: identifiant (0x10-0x13) et signature directe de la cle (0x1F, cles v6).
_SELF_SIGNATURE_TYPES = {0x10, 0x11, 0x12, 0x13, 0x1F}
#: Sous-paquets de signature : date de creation, duree de validite de la cle.
_SUB_CREATION, _SUB_KEY_EXPIRATION = 2, 9


@dataclass(frozen=True)
class KeyInfo:
    fingerprint: str
    version: int
    created_at: datetime
    expires_at: datetime | None
    user_ids: tuple

    @property
    def is_expired(self):
        return self.expires_at is not None and self.expires_at <= timezone.now()

    @property
    def readable_fingerprint(self):
        return " ".join(
            self.fingerprint[i : i + 4] for i in range(0, len(self.fingerprint), 4)
        )


def _dearmor(blob):
    lines = [line.strip() for line in blob.strip().splitlines()]
    try:
        start = lines.index(PUBLIC_KEY_HEADER) + 1
        end = lines.index(PUBLIC_KEY_FOOTER)
    except ValueError as exc:
        raise PGPError("Bloc de clé publique PGP invalide.") from exc
    body = lines[start:end]
    # En-tetes d'armure (« Comment: ... ») jusqu'a la premiere ligne vide.
    if "" in body:
        body = body[body.index("") + 1 :]
    data = "".join(line for line in body if line and not line.startswith("="))
    try:
        return base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise PGPError("Bloc de clé publique PGP illisible (base64 invalide).") from exc


def _packets(data):
    """(tag, corps) de chaque paquet, formats ancien et nouveau."""
    pos = 0
    while pos < len(data):
        header = data[pos]
        pos += 1
        if not header & 0x80:
            raise PGPError("Bloc de clé publique PGP illisible (paquet invalide).")
        if header & 0x40:
            tag = header & 0x3F
            first = data[pos]
            if first < 192:
                length, pos = first, pos + 1
            elif first < 224:
                length, pos = ((first - 192) << 8) + data[pos + 1] + 192, pos + 2
            elif first == 255:
                length, pos = int.from_bytes(data[pos + 1 : pos + 5], "big"), pos + 5
            else:
                raise PGPError("Bloc de clé publique PGP non pris en charge.")
        else:
            tag = (header >> 2) & 0x0F
            size = {0: 1, 1: 2, 2: 4}.get(header & 0x03)
            if size is None:
                raise PGPError("Bloc de clé publique PGP non pris en charge.")
            length, pos = int.from_bytes(data[pos : pos + size], "big"), pos + size
        if pos + length > len(data):
            raise PGPError("Bloc de clé publique PGP tronqué.")
        yield tag, data[pos : pos + length]
        pos += length


def _subpackets(area):
    pos = 0
    while pos < len(area):
        first = area[pos]
        if first < 192:
            length, pos = first, pos + 1
        elif first < 255:
            length, pos = ((first - 192) << 8) + area[pos + 1] + 192, pos + 2
        else:
            length, pos = int.from_bytes(area[pos + 1 : pos + 5], "big"), pos + 5
        if length == 0 or pos + length > len(area):
            return
        yield area[pos] & 0x7F, area[pos + 1 : pos + length]
        pos += length


def _self_signature(body):
    """(creation, duree de validite en secondes ou None) d'une auto-signature."""
    version = body[0]
    if version not in (4, 6) or body[1] not in _SELF_SIGNATURE_TYPES:
        return None
    size = 2 if version == 4 else 4
    hashed_length = int.from_bytes(body[4 : 4 + size], "big")
    area = body[4 + size : 4 + size + hashed_length]
    created, lifetime = None, None
    for kind, value in _subpackets(area):
        if kind == _SUB_CREATION and len(value) == 4:
            created = int.from_bytes(value, "big")
        elif kind == _SUB_KEY_EXPIRATION and len(value) == 4:
            lifetime = int.from_bytes(value, "big") or None
    return (created or 0), lifetime


def inspect_public_key(blob):
    """Empreinte, creation et expiration de la cle primaire d'un bloc armure.

    Leve PGPError si le bloc ne contient pas de cle publique lisible ou s'il
    contient une partie privee. L'expiration retenue est celle de
    l'auto-signature la plus recente, comme le font les clients OpenPGP.
    """
    primary, user_ids, signatures = None, [], []
    for tag, body in _packets(_dearmor(blob)):
        if tag in (_TAG_SECRET_KEY, _TAG_SECRET_SUBKEY):
            raise PGPError(
                "Ce bloc contient une clé privée : ne transmettez que la clé publique."
            )
        if tag == _TAG_PUBLIC_KEY and primary is None:
            primary = body
        elif tag == _TAG_USER_ID:
            user_ids.append(body.decode("utf-8", errors="replace"))
        elif tag == _TAG_SIGNATURE and primary is not None and len(body) > 8:
            signature = _self_signature(body)
            if signature is not None:
                signatures.append(signature)
    if primary is None or primary[0] not in (4, 6):
        raise PGPError("Aucune clé publique OpenPGP v4 ou v6 dans ce bloc.")
    version = primary[0]
    if version == 4:
        # SHA-1 impose par la RFC 4880 pour l'empreinte v4 : un identifiant,
        # pas une protection cryptographique.
        digest = hashlib.sha1(  # noqa: S324
            b"\x99" + len(primary).to_bytes(2, "big") + primary, usedforsecurity=False
        )
    else:
        digest = hashlib.sha256(b"\x9b" + len(primary).to_bytes(4, "big") + primary)
    created = datetime.fromtimestamp(int.from_bytes(primary[1:5], "big"), tz=UTC)
    expires = None
    if signatures:
        _created, lifetime = max(signatures, key=lambda item: item[0])
        if lifetime:
            expires = created + timedelta(seconds=lifetime)
    return KeyInfo(
        fingerprint=digest.hexdigest().upper(),
        version=version,
        created_at=created,
        expires_at=expires,
        user_ids=tuple(user_ids),
    )


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
    active = active_national_key()
    if active is not None:
        return active.public_key
    key = (settings.EVDP.get("PGP_PUBLIC_KEY") or "").strip()
    return key.replace("\\n", "\n")


def national_fingerprint():
    """Empreinte calculee depuis la cle publiee ; a defaut, celle du .env."""
    active = active_national_key()
    if active is not None:
        return active.readable_fingerprint
    key = national_public_key()
    if key:
        try:
            return inspect_public_key(key).readable_fingerprint
        except PGPError:
            pass
    return (settings.EVDP.get("PGP_FINGERPRINT") or "").strip()


def active_national_key():
    from .models import NationalPGPKey

    return NationalPGPKey.objects.filter(is_active=True).first()


def publish_national_key(blob, actor):
    """Valide puis publie une nouvelle cle nationale, en retirant l'ancienne."""
    from django.db import transaction

    from .models import NationalPGPKey

    blob = validate_public_key(blob)
    if not blob:
        raise PGPError("Collez le bloc de la clé publique.")
    info = inspect_public_key(blob)
    with transaction.atomic():
        NationalPGPKey.objects.filter(is_active=True).update(is_active=False)
        return NationalPGPKey.objects.create(
            public_key=blob,
            fingerprint=info.fingerprint,
            key_created_at=info.created_at,
            expires_at=info.expires_at,
            published_by=actor,
        )


#: Premier octet d'un message OpenPGP chiffre en binaire (RFC 4880/9580) :
#: paquet de cle de session chiffree par cle publique (tag 1) ou par mot de
#: passe (tag 3), au format ancien (0x84-0x87, 0x8C-0x8F) ou nouveau (0xC1, 0xC3).
_ENCRYPTED_PACKET_FIRST_BYTES = frozenset(
    {0x84, 0x85, 0x86, 0x87, 0x8C, 0x8D, 0x8E, 0x8F, 0xC1, 0xC3}
)


def is_binary_encrypted(head):
    """Le fichier commence-t-il par un message OpenPGP chiffre, non armure ?"""
    return bool(head) and head[0] in _ENCRYPTED_PACKET_FIRST_BYTES


#: Alerte avant l'expiration de la cle nationale : de quoi preparer la
#: rotation sans que les signaleurs chiffrent pour une cle perimee.
EXPIRY_WARNING_DAYS = 30


def national_key_expiring():
    """Cle nationale active qui expire dans moins de EXPIRY_WARNING_DAYS jours."""
    key = active_national_key()
    if key is None or key.expires_at is None:
        return None
    if key.expires_at - timezone.now() <= timedelta(days=EXPIRY_WARNING_DAYS):
        return key
    return None
