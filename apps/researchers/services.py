"""Services chercheurs : profil, reputation et portefeuille de versement.

La reputation n'est jamais modifiable par le chercheur : elle derive
exclusivement d'evenements emis par le moteur de coordination.
"""

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.vulnerabilities.constants import Severity

from .models import (
    IdentityMode,
    PayoutProfile,
    ReputationEvent,
    ReputationReason,
    ResearcherProfile,
)


def get_or_create_profile(user, **defaults):
    profile = getattr(user, "researcher_profile", None)
    if profile is not None:
        return profile
    defaults.setdefault("pseudonym", user.display_name or user.email.split("@")[0])
    defaults.setdefault("identity_mode", IdentityMode.PSEUDONYM)
    return ResearcherProfile.objects.create(user=user, **defaults)


def points_for(reason):
    """Bareme configurable (variables d'environnement EVDP_REP_*)."""
    return settings.EVDP["REPUTATION"].get(reason, 0)


@transaction.atomic
def grant(profile, reason, case=None, granted_by=None, note="", points=None):
    """Enregistre un evenement de reputation et met a jour les compteurs."""
    value = points_for(reason) if points is None else points
    event = ReputationEvent.objects.create(
        profile=profile,
        reason=reason,
        points=value,
        case=case,
        granted_by=granted_by,
        note=note[:255],
    )
    profile.recompute()
    return event


def award_reputation(user, case, granted_by=None):
    """Attribue les points liés à la validation d'un rapport.

    Un rapport valide rapporte les points de base ; une severite High ou
    Critical ouvre droit a un bonus. L'attribution est idempotente par case.
    """
    profile = getattr(user, "researcher_profile", None)
    if profile is None:
        return []
    if profile.reputation_events.filter(case=case, reason=ReputationReason.VALIDATED).exists():
        return []

    events = [grant(profile, ReputationReason.VALIDATED, case=case, granted_by=granted_by)]
    if case.severity == Severity.CRITICAL:
        events.append(
            grant(profile, ReputationReason.CRITICAL, case=case, granted_by=granted_by)
        )
    elif case.severity == Severity.HIGH:
        events.append(grant(profile, ReputationReason.HIGH, case=case, granted_by=granted_by))
    return events


def penalize_abuse(user, case=None, granted_by=None, note=""):
    profile = getattr(user, "researcher_profile", None)
    if profile is None:
        return None
    return grant(
        profile, ReputationReason.ABUSIVE, case=case, granted_by=granted_by, note=note
    )


def leaderboard(limit=20):
    return (
        ResearcherProfile.objects.filter(is_public_profile=True)
        .select_related("user")
        .order_by("-reputation", "-reports_validated")[:limit]
    )


# ---------------------------------------------------------------------------
# Portefeuille de versement
# ---------------------------------------------------------------------------
def get_or_create_payout_profile(user):
    profile = getattr(user, "payout_profile", None)
    if profile is not None:
        return profile
    return PayoutProfile.objects.create(user=user)


@transaction.atomic
def update_payout_profile(profile, actor, request=None):
    """Enregistre les informations personnelles de versement et l'audite.

    `actor` doit toujours etre le titulaire : ces donnees sont strictement
    en libre-service, aucun role ne peut modifier le portefeuille d'autrui.
    """
    if actor.pk != profile.user_id:
        raise PermissionDenied("Vous ne pouvez modifier que votre propre portefeuille.")
    profile.save()
    log_action(
        AuditAction.PAYOUT_PROFILE_UPDATED,
        actor=actor,
        obj=profile,
        request=request,
    )
    return profile


@transaction.atomic
def add_payout_method(profile, actor, method, request=None):
    """Enregistre un nouveau moyen de paiement pour le portefeuille.

    Le nombre de moyens actifs est borne (EVDP_MAX_PAYOUT_METHODS) pour
    empecher l'accumulation illimitee d'entrees sur un meme compte.
    """
    if actor.pk != profile.user_id:
        raise PermissionDenied("Vous ne pouvez modifier que votre propre portefeuille.")
    limit = settings.EVDP["MAX_PAYOUT_METHODS"]
    if profile.methods.filter(is_active=True).count() >= limit:
        raise ValidationError(f"Nombre maximum de moyens de paiement atteint ({limit}).")
    method.profile = profile
    if not profile.methods.filter(is_active=True).exists():
        # Le tout premier moyen declare devient principal par defaut.
        method.is_primary = True
    method.full_clean()
    method.save()
    log_action(
        AuditAction.PAYOUT_METHOD_ADDED,
        actor=actor,
        obj=method,
        request=request,
        method_type=method.method_type,
    )
    return method


@transaction.atomic
def update_payout_method(method, actor, request=None):
    if actor.pk != method.profile.user_id:
        raise PermissionDenied("Vous ne pouvez modifier que votre propre portefeuille.")
    method.full_clean()
    method.save()
    log_action(
        AuditAction.PAYOUT_METHOD_UPDATED,
        actor=actor,
        obj=method,
        request=request,
        method_type=method.method_type,
    )
    return method


@transaction.atomic
def set_primary_payout_method(method, actor, request=None):
    if actor.pk != method.profile.user_id:
        raise PermissionDenied("Vous ne pouvez modifier que votre propre portefeuille.")
    if not method.is_active:
        raise ValidationError("Un moyen retire ne peut pas devenir principal.")
    method.is_primary = True
    method.save(update_fields=["is_primary", "updated_at"])
    log_action(
        AuditAction.PAYOUT_METHOD_UPDATED,
        actor=actor,
        obj=method,
        request=request,
        set_primary=True,
    )
    return method


@transaction.atomic
def remove_payout_method(method, actor, request=None):
    """Desactive un moyen de paiement (jamais de suppression physique :
    la trace reste disponible pour l'audit)."""
    if actor.pk != method.profile.user_id:
        raise PermissionDenied("Vous ne pouvez modifier que votre propre portefeuille.")
    method.is_active = False
    method.is_primary = False
    method.save(update_fields=["is_active", "is_primary", "updated_at"])
    log_action(
        AuditAction.PAYOUT_METHOD_REMOVED,
        actor=actor,
        obj=method,
        request=request,
        method_type=method.method_type,
    )
    # Si le moyen retire etait le seul, aucun autre n'est promu
    # automatiquement : le chercheur choisit lui-meme son nouveau principal.
    return method
