"""Services chercheurs : profil et reputation.

La reputation n'est jamais modifiable par le chercheur : elle derive
exclusivement d'evenements emis par le moteur de coordination.
"""

from django.conf import settings
from django.db import transaction

from apps.vulnerabilities.constants import Severity

from .models import IdentityMode, ReputationEvent, ReputationReason, ResearcherProfile


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
