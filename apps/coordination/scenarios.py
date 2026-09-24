"""Parcours scriptes du workflow v2 (jeu de demonstration, tests).

Chaque etape est jouee par son proprietaire, avec les donnees exigees par
ses pre-requis : le parcours emprunte exactement le chemin de l'interface
(services + check_transition), sans raccourci.
"""

from dataclasses import dataclass
from datetime import timedelta

from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import log_action

from . import services
from .workflow import CaseStatus as S

#: Ordre du chemin principal.
MAIN_PATH = [
    S.SUBMITTED,
    S.ACKNOWLEDGED,
    S.IN_ANALYSIS,
    S.VALIDATION_PENDING,
    S.VALIDATED,
    S.VENDOR_NOTIFIED,
    S.REMEDIATION_IN_PROGRESS,
    S.FIX_AVAILABLE,
    S.FIX_VERIFIED,
    S.ADVISORY_REVIEW,
    S.CLOSED,
]

DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"


@dataclass
class Team:
    """Les proprietaires des etapes."""

    triager: object
    analyst: object
    validator: object  # Coordinateur ou analyste senior
    vendor: object  # DSI ou responsable d'organisation
    publisher: object  # Coordinateur


def open_case(case, user):
    """Trace l'ouverture du dossier (pre-requis de l'accuse de reception)."""
    log_action(AuditAction.CASE_VIEWED, actor=user, obj=case)


def _step(case, team, cwe=None, cvss_vector=DEFAULT_VECTOR, organization=None):
    """Joue l'etape courante et rend le nouveau statut."""
    status = case.status
    if status == S.SUBMITTED:
        open_case(case, team.triager)
        services.transition_case(case, "acknowledge", team.triager)
    elif status == S.ACKNOWLEDGED:
        services.record_admissibility(case, team.triager, True, True, True)
        services.transition_case(case, "declare_admissible", team.triager)
    elif status == S.IN_ANALYSIS:
        services.set_severity(case, team.analyst, cvss_vector=cvss_vector)
        updates = []
        if cwe is not None and case.cwe_id is None:
            case.cwe = cwe
            updates.append("cwe")
        if organization is not None and case.organization_id is None:
            case.organization = organization
            updates.append("organization")
        if updates:
            case.save(update_fields=updates + ["updated_at"])
        services.transition_case(case, "submit_qualification", team.analyst)
    elif status == S.VALIDATION_PENDING:
        services.transition_case(
            case, "validate_qualification", team.validator, comment="Qualification validée."
        )
    elif status == S.VALIDATED:
        services.record_vendor_summary(case, team.analyst, services.build_vendor_summary(case))
        services.transition_case(case, "notify_vendor", team.analyst)
    elif status == S.VENDOR_NOTIFIED:
        services.record_remediation_plan(
            case,
            team.vendor,
            "Correction du composant vulnérable et déploiement en production.",
            timezone.localdate() + timedelta(days=20),
        )
        services.transition_case(case, "submit_remediation_plan", team.vendor)
    elif status == S.REMEDIATION_IN_PROGRESS:
        services.record_fix(
            case, team.vendor, "Requêtes paramétrées et validation des entrées.", "2.4.1"
        )
        services.transition_case(case, "declare_fix", team.vendor)
    elif status == S.FIX_AVAILABLE:
        services.record_fix_verification(
            case,
            team.analyst,
            "Contre-vérification effectuée : la faille n'est plus exploitable.",
        )
        services.transition_case(case, "verify_fix", team.analyst)
    elif status == S.FIX_VERIFIED:
        from apps.disclosures.services import create_advisory_from_case

        if case.current_advisory() is None:
            create_advisory_from_case(
                case,
                team.analyst,
                summary="Une vulnérabilité a été corrigée par l'organisation concernée.",
                solution="Appliquer la mise à jour fournie par l'éditeur.",
            )
        services.transition_case(case, "submit_advisory", team.analyst)
    elif status == S.ADVISORY_REVIEW:
        services.transition_case(
            case, "publish_and_close", team.publisher, comment="Relecture faite."
        )
    else:
        raise ValueError(f"Aucune etape scriptee depuis {status}.")
    case.refresh_from_db()
    return case.status


def advance_case(case, until, team, **options):
    """Fait avancer `case` sur le chemin principal jusqu'a `until` inclus."""
    target_index = MAIN_PATH.index(until)
    while case.status in MAIN_PATH and MAIN_PATH.index(case.status) < target_index:
        _step(case, team, **options)
    return case
