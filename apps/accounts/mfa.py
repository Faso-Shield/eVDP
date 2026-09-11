"""Double authentification par code TOTP (RFC 6238).

Le second facteur ne vise pas tout le monde. Un compte signaleur n'a acces
qu'a ses propres rapports : lui imposer un authentificateur ajouterait une
barriere a l'entree d'un dispositif dont la valeur tient a ce qu'on puisse y
signaler facilement. Les comptes administrateurs et metiers, eux, voient les
dossiers d'autrui, changent des statuts, approuvent des recompenses : leur
compromission porte sur la plateforme entiere.

La regle est donc portee par le role, pas par un reglage par compte : voir
`is_required`. Elle n'est jamais lue depuis le client.

TOTP uniquement : ni SMS ni email, dont l'acheminement n'est pas maitrise par
la plateforme et dont l'interception est un scenario documente.
"""

import time

import pyotp
from django.conf import settings

from .roles import RESEARCHER_ROLES

#: Longueur du code attendu, et pas de temps en secondes (valeurs RFC 6238
#: par defaut, celles qu'appliquent les authentificateurs courants).
CODE_LENGTH = 6
INTERVAL = 30

#: Tolerance de derive d'horloge, en pas de temps de part et d'autre.
#: Un pas suffit : au-dela, on accepterait un code vieux d'une minute et demie.
DRIFT_STEPS = 1


def is_required(user):
    """Le second facteur s'applique-t-il a ce compte ?

    Vrai pour tout compte qui n'est pas un signaleur : administrateurs,
    coordination nationale, analystes, triage, DSI, responsables
    d'organisation, auditeurs. Ces comptes sont crees par un administrateur,
    jamais par l'inscription publique.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return False
    if not user.is_active:
        return False
    return user.role not in RESEARCHER_ROLES


def issuer():
    return settings.EVDP["PLATFORM_NAME"]


def new_secret():
    return pyotp.random_base32()


def provisioning_uri(user, secret):
    """URI `otpauth://` a saisir dans l'authentificateur."""
    return pyotp.TOTP(secret, interval=INTERVAL, digits=CODE_LENGTH).provisioning_uri(
        name=user.email, issuer_name=issuer()
    )


def readable_secret(secret):
    """Secret en groupes de quatre, pour une saisie manuelle sans faute."""
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def matching_step(secret, code, now=None):
    """Pas de temps auquel `code` est valide, None s'il ne l'est pour aucun.

    On rend le pas plutot qu'un booleen : c'est lui qui permet de refuser le
    rejeu. `pyotp.verify(valid_window=1)` accepterait le code sans dire a
    quel instant il correspond, et un code intercepte resterait utilisable
    pendant toute sa fenetre.
    """
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != CODE_LENGTH:
        return None
    totp = pyotp.TOTP(secret, interval=INTERVAL, digits=CODE_LENGTH)
    instant = int(now if now is not None else time.time())
    for decalage in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        candidat = instant + decalage * INTERVAL
        if totp.verify(code, for_time=candidat):
            return candidat // INTERVAL
    return None


def consume_code(user, code, now=None):
    """Verifie un code et le brule. Vrai s'il etait valide et inedit.

    Le pas consomme est enregistre sur le compte : un code rejoue dans sa
    propre fenetre, ou un code anterieur encore dans la tolerance de derive,
    est refuse.
    """
    pas = matching_step(user.mfa_secret, code, now=now)
    if pas is None:
        return False
    if user.mfa_last_step and pas <= user.mfa_last_step:
        return False
    user.mfa_last_step = pas
    user.save(update_fields=["mfa_last_step", "updated_at"])
    return True
