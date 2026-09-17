"""Utilitaires transverses."""

import hashlib
import secrets
import string

from django.db import transaction
from django.utils import timezone

ALPHABET = string.ascii_lowercase + string.digits


def random_token(length=48):
    return secrets.token_urlsafe(length)[:length]


def random_slug(length=16):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def sha256_hexdigest(chunks):
    """Empreinte SHA-256 d'un iterable de blocs binaires."""
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def hash_text(text):
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def next_sequence(model, field, prefix, year=None, width=6):
    """Genere un identifiant lisible sequentiel du type EVDP-2026-000001.

    La generation est verrouillee dans une transaction afin d'eviter les
    collisions lorsque plusieurs rapports arrivent simultanement.
    """
    year = year or timezone.now().year
    pattern = f"{prefix}-{year}-"
    with transaction.atomic():
        last = (
            model.objects.select_for_update()
            .filter(**{f"{field}__startswith": pattern})
            .order_by(f"-{field}")
            .values_list(field, flat=True)
            .first()
        )
        counter = int(last.rsplit("-", 1)[1]) + 1 if last else 1
        return f"{pattern}{counter:0{width}d}"


def truncate(text, limit=120):
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def mask_value(value, keep=4):
    """Masque une donnee sensible (IBAN, numero mobile money...) en ne
    conservant que les `keep` derniers caracteres. Usage : affichage dans
    les listes, jamais dans un formulaire d'edition (voir apps.researchers).
    """
    value = (value or "").strip()
    if not value:
        return "—"
    if len(value) <= keep:
        return "•" * len(value)
    return "•" * (len(value) - keep) + value[-keep:]
