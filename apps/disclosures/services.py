"""Redaction et publication des advisories.

Principe 5 : aucune donnee interne du case n'est exposee publiquement.
Principe 6 : l'advisory est une representation assainie, construite par un
analyste a partir de champs explicitement selectionnes.
"""

import re

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.constants import TimelineEventType
from apps.coordination.services import add_timeline_event
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify

from .models import Advisory, AdvisoryStatus, AdvisoryTimelineEntry


def credit_for(case):
    """Credit public respectant le choix d'identite du chercheur."""
    report = getattr(case, "report", None)
    if report is None or not report.wants_credit or report.is_anonymous:
        return "Chercheur anonyme"
    if case.reporter_id:
        return case.reporter.public_identity()
    return report.reporter_name or "Chercheur anonyme"


#: Lignes d'un texte de declarant qui trahissent une preuve de concept.
_POC_LINE = re.compile(
    r"(curl |wget |<script|union select|/etc/passwd|or 1=1|payload|exploit)",
    re.IGNORECASE,
)
_CODE_BLOCK = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`]*`")
_URL_TEXT = re.compile(r"\b(?:https?|ftp)://\S+", re.IGNORECASE)
_IP_TEXT = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b",
    re.IGNORECASE,
)


def sanitize_for_advisory(text):
    """Texte du dossier rendu publiable : sans code, URL, adresse IP ni PoC.

    Proposition de depart seulement : le redacteur relit, et l'etape 9
    refuse de toute facon un brouillon non assaini.
    """
    text = _CODE_BLOCK.sub("", text or "")
    text = _INLINE_CODE.sub("[élément technique retiré]", text)
    text = _URL_TEXT.sub("[URL retirée]", text)
    text = _IP_TEXT.sub("[adresse retirée]", text)
    lines = [line for line in text.splitlines() if not _POC_LINE.search(line)]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def advisory_proposal(case):
    """Proposition d'advisory tenant compte de tout le dossier a ce stade.

    Qualification (type, CWE, CVSS, severite), produit et versions,
    organisation, correctif declare et contre-verification : autant de
    champs structures, deja valides par le workflow. Le texte libre du
    declarant (description, impact, recommandations) n'est repris
    qu'assaini.
    """
    report = case.report
    kind = case.get_vulnerability_type_display()
    product = case.product or "le produit concerné"
    owner = case.organization.name if case.organization_id else ""
    cwe = f" ({case.cwe.code})" if case.cwe_id else ""
    cvss = f", score CVSS {case.cvss_score}" if case.cvss_score is not None else ""
    fixed = case.fix_version or report.fixed_version
    affected = report.affected_version or (f"< {fixed}" if fixed else "")

    summary = (
        f"Une vulnérabilité de type {kind}{cwe}, de sévérité "
        f"{case.get_severity_display().lower()}{cvss}, affectait {product}"
        f"{f' de {owner}' if owner else ''}. "
    )
    summary += (
        f"Un correctif est disponible{f' (version {fixed})' if fixed else ''} et a été "
        "vérifié par le CSIRT national."
        if case.fix_description or fixed
        else "Aucun correctif n'est encore disponible : appliquez les mesures de "
        "contournement ci-dessous."
    )

    description = sanitize_for_advisory(report.description)
    if description:
        description = f"{description}\n\n"
    description += f"Catégorie : {kind}{cwe}."
    if case.cvss_vector:
        description += f"\n\nVecteur CVSS : `{case.cvss_vector}`"

    solution_parts = []
    if case.fix_description:
        solution_parts.append(sanitize_for_advisory(case.fix_description))
    if fixed:
        solution_parts.append(f"Mettre à jour vers la version {fixed} ou ultérieure.")
    if case.fix_deployed_on:
        solution_parts.append(f"Correctif déployé le {case.fix_deployed_on:%d/%m/%Y}.")
    if not solution_parts and report.recommendations:
        solution_parts.append(sanitize_for_advisory(report.recommendations))

    return {
        "title": f"{kind} dans {product}" if case.product else case.title,
        "summary": summary,
        "description": description,
        "impact": sanitize_for_advisory(report.impact),
        "solution": "\n\n".join(part for part in solution_parts if part),
        "workaround": ""
        if case.fix_description or fixed
        else sanitize_for_advisory(report.recommendations),
        "affected_versions": affected[:255],
        "fixed_versions": (fixed or "")[:255],
    }


@transaction.atomic
def create_advisory_from_case(case, actor, request=None, **overrides):
    """Prepare un brouillon d'advisory a partir d'un case valide.

    Le brouillon est une proposition complete (voir advisory_proposal) : il
    reprend toutes les informations du dossier a ce stade, sans jamais
    recopier la preuve de concept, les etapes de reproduction, l'URL cible
    ni les pieces jointes.
    """
    if not (
        actor.has_capability(Capability.DRAFT_ADVISORY)
        or actor.has_capability(Capability.PUBLISH_ADVISORY)
    ):
        raise PermissionDenied("Capacité requise pour rédiger un advisory.")

    proposal = advisory_proposal(case)
    data = {
        "case": case,
        "organization": case.organization,
        **proposal,
        "product": case.product,
        "severity": case.severity,
        "cvss_score": case.cvss_score,
        "cvss_vector": case.cvss_vector,
        "cwe": case.cwe,
        "cve": case.cve,
        "credit": credit_for(case),
        "created_by": actor,
        "status": AdvisoryStatus.DRAFT,
    }
    data.update(overrides)
    advisory = Advisory.objects.create(**data)
    # Journal lisible : d'ou vient la proposition.
    proposal_sources = sorted(key for key, value in proposal.items() if value)

    # Chronologie publique : uniquement les jalons marques publics.
    for index, event in enumerate(case.timeline.filter(is_public=True)):
        AdvisoryTimelineEntry.objects.create(
            advisory=advisory,
            happened_on=timezone.localtime(event.occurred_at).date(),
            label=event.label,
            position=index,
        )

    log_action(
        AuditAction.ADVISORY_CREATED,
        actor=actor,
        obj=advisory,
        request=request,
        case=case.case_id,
        prefilled=proposal_sources,
    )
    return advisory


@transaction.atomic
def create_advisory(advisory, actor, case=None, request=None):
    """Enregistre un advisory redige a la main.

    Complement de `create_advisory_from_case` pour les advisories sans case
    source. La vue ne sauvegarde jamais le modele elle-meme : l'ecriture passe
    ici afin que la creation soit toujours auditee.
    """
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacité requise pour rédiger un advisory.")

    advisory.created_by = actor
    if case is not None:
        advisory.case = case
        advisory.organization = case.organization
    advisory.save()

    log_action(
        AuditAction.ADVISORY_CREATED,
        actor=actor,
        obj=advisory,
        request=request,
        case=case.case_id if case is not None else None,
    )
    return advisory


@transaction.atomic
def update_advisory(advisory, actor, request=None):
    """Enregistre une modification redactionnelle et l'audite.

    Un advisory publie reste modifiable (correction editoriale), mais chaque
    modification laisse une trace nominative.
    """
    if not (
        actor.has_capability(Capability.DRAFT_ADVISORY)
        or actor.has_capability(Capability.PUBLISH_ADVISORY)
    ):
        raise PermissionDenied("Capacite requise pour modifier un advisory.")

    advisory.save()
    log_action(
        AuditAction.ADVISORY_UPDATED,
        actor=actor,
        obj=advisory,
        request=request,
        status=advisory.status,
    )
    return advisory


@transaction.atomic
def transition_advisory(advisory, target_status, actor, request=None):
    if target_status == AdvisoryStatus.PUBLISHED:
        return publish_advisory(advisory, actor, request=request)
    if not actor.has_capability(Capability.DRAFT_ADVISORY):
        raise PermissionDenied("Capacité requise.")
    if not advisory.can_transition_to(target_status):
        raise ValidationError(f"Transition interdite : {advisory.status} -> {target_status}.")
    advisory.status = target_status
    advisory.save(update_fields=["status", "updated_at"])
    log_action(
        AuditAction.ADVISORY_UPDATED,
        actor=actor,
        obj=advisory,
        request=request,
        to_status=target_status,
    )
    return advisory


@transaction.atomic
def publish_advisory(advisory, actor, request=None, published_at=None, from_workflow=False):
    """Publie l'advisory. Action irreversible hors retrait explicite.

    Un advisory issu d'un dossier se publie par l'etape 10 du workflow
    (« Publier et clôturer »), qui porte la relecture, le controle du credit,
    la fin de la branche prime et la regle des quatre yeux : il ne peut pas
    etre publie a cote.
    """
    if not actor.has_capability(Capability.PUBLISH_ADVISORY):
        raise PermissionDenied("Capacité requise pour publier un advisory.")
    if advisory.case_id and not from_workflow and advisory.case.status != "CLOSED":
        raise ValidationError(
            "Cet advisory est lié à un dossier : il se publie par « Publier et "
            "clôturer » sur le dossier (étape 10 du workflow)."
        )
    if not advisory.can_transition_to(AdvisoryStatus.PUBLISHED):
        raise ValidationError("Un advisory doit être approuvé ou planifié avant publication.")
    if not advisory.summary.strip():
        raise ValidationError({"summary": "Un résumé public est obligatoire."})

    advisory.status = AdvisoryStatus.PUBLISHED
    advisory.published_at = published_at or timezone.now()
    advisory.published_by = actor
    advisory.save(update_fields=["status", "published_at", "published_by", "updated_at"])

    log_action(
        AuditAction.ADVISORY_PUBLISHED,
        actor=actor,
        obj=advisory,
        request=request,
        case=advisory.case.case_id if advisory.case_id else None,
    )

    if advisory.case_id:
        add_timeline_event(
            advisory.case,
            TimelineEventType.ADVISORY_PUBLISHED,
            f"Advisory {advisory.advisory_id} publie",
            actor=actor,
        )
        if advisory.case.reporter_id:
            notify(
                advisory.case.reporter,
                NotificationKind.ADVISORY_PUBLISHED,
                case=advisory.case,
                url=advisory.get_absolute_url(),
            )
    return advisory


@transaction.atomic
def retract_advisory(advisory, actor, reason, request=None):
    if not actor.has_capability(Capability.PUBLISH_ADVISORY):
        raise PermissionDenied("Capacité requise.")
    if not advisory.can_transition_to(AdvisoryStatus.RETRACTED):
        raise ValidationError("Seul un advisory publié peut être retiré.")
    if not reason.strip():
        raise ValidationError({"reason": "Un motif de retrait est obligatoire."})
    advisory.status = AdvisoryStatus.RETRACTED
    advisory.retracted_reason = reason
    advisory.save(update_fields=["status", "retracted_reason", "updated_at"])
    log_action(
        AuditAction.ADVISORY_RETRACTED,
        actor=actor,
        obj=advisory,
        request=request,
        reason=reason[:200],
    )
    return advisory
