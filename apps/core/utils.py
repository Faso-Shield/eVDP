"""Utilitaires transverses."""

import hashlib
import secrets
import string

from django.db import IntegrityError, transaction
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

    Utilise un compteur dedie (SequenceCounter), verrouille et incremente
    sur place. Deriver le prochain numero du "dernier" enregistrement
    existant (comme avant) ne verrouille que des lignes deja commitees :
    deux transactions concurrentes peuvent lire le meme "dernier" numero,
    toutes deux le locker sans se bloquer mutuellement (aucune des deux ne
    modifie cette ligne), puis tenter de creer le meme identifiant, l'une
    des deux echouant sur la contrainte d'unicite. Incrementer une ligne de
    compteur qui existe deja et qu'on modifie reellement force en revanche
    une vraie serialisation via le verrou de ligne.
    """
    from apps.core.models import SequenceCounter

    year = year or timezone.now().year
    pattern = f"{prefix}-{year}-"
    counter_key = f"{model._meta.label}:{field}:{pattern}"
    with transaction.atomic():
        try:
            with transaction.atomic():
                SequenceCounter.objects.create(key=counter_key, last_value=0)
        except IntegrityError:
            pass
        counter = SequenceCounter.objects.select_for_update().get(key=counter_key)
        counter.last_value += 1
        counter.save(update_fields=["last_value"])
        return f"{pattern}{counter.last_value:0{width}d}"


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
