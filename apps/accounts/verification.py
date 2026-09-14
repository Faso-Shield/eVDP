"""Delai de grace sur l'exigence d'adresse email verifiee.

Exiger une adresse verifiee prive du jour au lendemain les comptes deja en
base qui ne l'ont jamais fait. Ce module accorde un sursis a ces seuls
comptes : ceux crees **avant** l'entree en vigueur de la regle disposent d'un
delai pour se mettre a jour, pendant lequel ils sont relances.

Les comptes crees apres l'entree en vigueur n'ont aucun sursis : leur donner
un delai reviendrait a laisser une adresse non controlee participer a un Bug
Bounty, ce que la regle vise precisement a empecher.

L'entree en vigueur n'est pas datee dans le code : elle est portee par
`EVDP_VERIFICATION_ENFORCED_FROM`, que chaque deploiement fixe a sa propre
date de bascule. Non renseignee, aucun sursis n'est accorde.
"""

from datetime import date, timedelta

from django.conf import settings


def enforcement_date():
    """Date de bascule, ou None si la regle s'applique sans sursis."""
    brut = (settings.EVDP.get("VERIFICATION_ENFORCED_FROM") or "").strip()
    if not brut:
        return None
    try:
        return date.fromisoformat(brut)
    except ValueError:
        # Une date malformee ne doit pas ouvrir un sursis indefini ni faire
        # tomber l'application : on retombe sur le comportement strict.
        return None


def grace_deadline(user):
    """Derniere date ou `user` participe sans avoir verifie son adresse.

    None si le compte n'a droit a aucun sursis : adresse deja verifiee,
    regle sans date de bascule, ou compte cree apres celle-ci.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    if getattr(user, "email_verified", False):
        return None
    bascule = enforcement_date()
    if bascule is None:
        return None
    cree_le = getattr(user, "created_at", None)
    if cree_le is None or cree_le.date() >= bascule:
        return None
    return bascule + timedelta(days=int(settings.EVDP["VERIFICATION_GRACE_DAYS"]))


def is_within_grace(user, today=None):
    """Vrai tant que le sursis de `user` court encore."""
    from django.utils import timezone

    echeance = grace_deadline(user)
    return echeance is not None and (today or timezone.localdate()) <= echeance


def reminder_days():
    """Nombre de jours restants declenchant une relance."""
    return sorted({int(j) for j in settings.EVDP["VERIFICATION_REMINDER_DAYS"]}, reverse=True)


def accounts_losing_access(days_left=1, today=None):
    """Comptes non verifies dont le sursis expire dans au plus `days_left` jours.

    L'echeance est commune a toute la cohorte : elle depend de la date de
    bascule, pas de chaque compte. La requete se resume donc a un test de
    date, suivi du filtre d'eligibilite au sursis.

    Les comptes dont le sursis a deja expire restent listes : ce sont
    precisement ceux qu'il faut rattraper autrement, la relance par email
    ayant echoue.
    """
    from django.utils import timezone

    from .models import User

    bascule = enforcement_date()
    if bascule is None:
        return User.objects.none()

    echeance = bascule + timedelta(days=int(settings.EVDP["VERIFICATION_GRACE_DAYS"]))
    jour = today or timezone.localdate()
    if (echeance - jour).days > days_left:
        return User.objects.none()

    return User.objects.filter(
        is_active=True, email_verified=False, created_at__date__lt=bascule
    )
