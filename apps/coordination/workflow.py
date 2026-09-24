"""Machine a etats du traitement des dossiers -- Workflow v2.

Reference : « Workflow v2 & Matrice RBAC » (alignee sur SPEC-eVDP-2026-V2).

Principes appliques ici, et verifies cote serveur par `check_transition()` :

  * Un bouton, un role : chaque etape du chemin principal a une seule action
    principale, portee par une seule capacite.
  * Pre-requis bloquants : l'action reste refusee tant qu'un champ exige
    manque, avec la liste explicite de ce qui manque.
  * Quatre yeux : qualification, prime, rejet et publication sont valides par
    une personne differente de l'auteur de l'etape precedente -- le controle
    porte sur l'utilisateur, pas seulement sur le role.
  * Exceptions a part : complements, rejet, doublon, renvoi et escalade sont
    des actions secondaires, jamais des boutons de validation.

Chemin principal (11 etapes, 10 clics) :

  SUBMITTED -> ACKNOWLEDGED -> IN_ANALYSIS -> VALIDATION_PENDING -> VALIDATED
  -> VENDOR_NOTIFIED -> REMEDIATION_IN_PROGRESS -> FIX_AVAILABLE
  -> FIX_VERIFIED -> ADVISORY_REVIEW -> CLOSED

Branche Bug Bounty, ouverte des VALIDATED et portee par un champ distinct
(`Case.bounty_stage`) : BOUNTY_ELIGIBLE -> BOUNTY_PROPOSED -> BOUNTY_CREDITED,
ou NOT_ELIGIBLE pour un programme non eligible.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import timedelta

from django.db import models
from django.utils import timezone

from apps.accounts.roles import Capability


class CaseStatus(models.TextChoices):
    # -- Chemin principal --------------------------------------------------
    SUBMITTED = "SUBMITTED", "Soumis"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Réception accusée"
    IN_ANALYSIS = "IN_ANALYSIS", "En analyse"
    VALIDATION_PENDING = "VALIDATION_PENDING", "Qualification à valider"
    VALIDATED = "VALIDATED", "Validé"
    VENDOR_NOTIFIED = "VENDOR_NOTIFIED", "Organisation notifiée"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS", "Remédiation en cours"
    FIX_AVAILABLE = "FIX_AVAILABLE", "Correctif disponible"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    ADVISORY_REVIEW = "ADVISORY_REVIEW", "Advisory en relecture"
    CLOSED = "CLOSED", "Clos"
    # -- Sorties d'exception -------------------------------------------------
    NEEDS_INFORMATION = "NEEDS_INFORMATION", "Compléments demandés"
    REJECTION_PENDING = "REJECTION_PENDING", "Rejet proposé"
    REJECTED = "REJECTED", "Rejeté"
    DUPLICATE = "DUPLICATE", "Doublon"

    @classmethod
    def validated_states(cls):
        """Etats attestant qu'un rapport a ete reconnu comme valide."""
        return [
            cls.VALIDATED,
            cls.VENDOR_NOTIFIED,
            cls.REMEDIATION_IN_PROGRESS,
            cls.FIX_AVAILABLE,
            cls.FIX_VERIFIED,
            cls.ADVISORY_REVIEW,
            cls.CLOSED,
        ]

    @classmethod
    def open_states(cls):
        return [s for s in cls.values if s not in TERMINAL_STATES]


class BountyStage(models.TextChoices):
    """Statut de prime : champ distinct du statut du dossier."""

    NONE = "", "—"
    ELIGIBLE = "BOUNTY_ELIGIBLE", "Éligible à une prime"
    PROPOSED = "BOUNTY_PROPOSED", "Prime proposée"
    CREDITED = "BOUNTY_CREDITED", "Prime créditée"
    NOT_ELIGIBLE = "NOT_ELIGIBLE", "Non éligible"


#: Statuts de prime qui laissent le dossier se clore (etape 10).
BOUNTY_FINAL_STAGES = frozenset({BountyStage.CREDITED, BountyStage.NOT_ELIGIBLE})

#: Chemin principal, dans l'ordre : sert aux libelles d'etape et aux renvois.
MAIN_PATH = [
    CaseStatus.SUBMITTED,
    CaseStatus.ACKNOWLEDGED,
    CaseStatus.IN_ANALYSIS,
    CaseStatus.VALIDATION_PENDING,
    CaseStatus.VALIDATED,
    CaseStatus.VENDOR_NOTIFIED,
    CaseStatus.REMEDIATION_IN_PROGRESS,
    CaseStatus.FIX_AVAILABLE,
    CaseStatus.FIX_VERIFIED,
    CaseStatus.ADVISORY_REVIEW,
    CaseStatus.CLOSED,
]

#: Etats terminaux : plus aucune transition sortante.
TERMINAL_STATES = frozenset({CaseStatus.CLOSED, CaseStatus.REJECTED, CaseStatus.DUPLICATE})

#: Etats consideres comme "resolus sans suite".
DISMISSED_STATES = frozenset({CaseStatus.REJECTED, CaseStatus.DUPLICATE})

#: Etapes 1 a 3 : celles ou complements, rejet et doublon peuvent etre demandes.
EARLY_STATES = (CaseStatus.SUBMITTED, CaseStatus.ACKNOWLEDGED, CaseStatus.IN_ANALYSIS)

#: Etats a partir desquels l'organisation affectee voit le dossier (etape 5).
#: Jamais avant que le CSIRT ne l'ait explicitement notifiee : pendant le
#: triage et l'analyse, le declarant doit rester protege d'une reaction
#: prematuree de l'organisation sur un signalement encore non valide.
ORG_VISIBLE_STATES = frozenset(
    {
        CaseStatus.VENDOR_NOTIFIED,
        CaseStatus.REMEDIATION_IN_PROGRESS,
        CaseStatus.FIX_AVAILABLE,
        CaseStatus.FIX_VERIFIED,
        CaseStatus.ADVISORY_REVIEW,
        CaseStatus.CLOSED,
    }
)

#: Comptes metiers dont le perimetre suit l'etape en cours : ils ne voient un
#: dossier (liste, Kanban, fiche, API) et n'agissent dessus que lorsqu'ils en
#: sont responsables. Un dossier escalade devient une etape du Coordinateur.
#: Restent hors de cette regle l'auditeur (aucune etape : metadonnees en vue
#: nationale) et le super admin (aucun dossier).
STEP_SCOPED_ROLES = frozenset(
    {
        "TRIAGER",
        "CSIRT_ANALYST",
        "NATIONAL_COORDINATOR",
        "DSI_ADMIN",
        "ORGANIZATION_MANAGER",
    }
)

#: Etapes ou l'escalade (manuelle ou automatique sur SLA depasse) s'applique.
ESCALATION_STATES = (CaseStatus.VENDOR_NOTIFIED, CaseStatus.REMEDIATION_IN_PROGRESS)

#: Delai apres la notification de l'organisation au-dela duquel le
#: Coordinateur peut decider une divulgation a echeance.
DEADLINE_DISCLOSURE_DAYS = 90

#: Sans reponse du declarant dans ce delai, le rejet est propose d'office.
NEEDS_INFORMATION_TIMEOUT_DAYS = 30


# ---------------------------------------------------------------------------
# Libelles
# ---------------------------------------------------------------------------
class Owner:
    """Libelles des roles proprietaires d'une etape (« En attente de : … »)."""

    REPORTER = "Déclarant"
    TRIAGER = "Agent de triage"
    ANALYST = "Analyste CSIRT"
    COORDINATOR = "Coordinateur"
    VALIDATOR = "Coordinateur ou analyste senior"
    VENDOR = "Responsable DSI"
    SYSTEM = "Système"


# ---------------------------------------------------------------------------
# Pre-requis
# ---------------------------------------------------------------------------
#: Motifs interdits dans un brouillon d'advisory : un advisory est public.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s)>\]]+", re.IGNORECASE)
_POC_MARKERS = (
    "```",
    "<script",
    "curl ",
    "wget ",
    "' or 1=1",
    '" or 1=1',
    "union select",
    "/etc/passwd",
    "proof of concept",
    "preuve de concept",
)
_SENSITIVE_HOST_SUFFIXES = (".local", ".lan", ".internal", ".intra", ".corp", ".localhost")
_SENSITIVE_URL_MARKERS = ("token=", "key=", "password=", "passwd=", "secret=", "session=", "@")


def _url_is_sensitive(url):
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    host = (parts.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host == "localhost" or host.endswith(_SENSITIVE_HOST_SUFFIXES):
        return True
    return any(marker in url.lower() for marker in _SENSITIVE_URL_MARKERS)


def advisory_sanitization_issues(advisory):
    """Liste ce qui empeche un brouillon d'advisory d'etre juge assaini.

    Controle volontairement conservateur : aucun PoC, aucune adresse IP,
    aucune URL sensible (hote interne, adresse IP, jeton ou identifiant).
    """
    text = "\n".join(
        getattr(advisory, name, "") or ""
        for name in ("title", "summary", "description", "impact", "solution", "workaround")
    )
    lowered = text.lower()
    issues = []
    if any(marker in lowered for marker in _POC_MARKERS):
        issues.append("Le brouillon contient un élément de preuve de concept")
    for candidate in _IPV4.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        issues.append("Le brouillon contient une adresse IP")
        break
    else:
        if _IPV6.search(text):
            issues.append("Le brouillon contient une adresse IP")
    if any(_url_is_sensitive(url) for url in _URL.findall(text)):
        issues.append("Le brouillon contient une URL sensible")
    return issues


def working_advisory(case):
    """Brouillon d'advisory en cours pour ce dossier (le plus recent)."""
    from apps.disclosures.models import AdvisoryStatus

    return (
        case.advisories.exclude(
            status__in=[AdvisoryStatus.PUBLISHED, AdvisoryStatus.RETRACTED]
        )
        .order_by("-created_at")
        .first()
    )


def remediation_limit_days(case):
    """Delai maximal de remediation selon la severite (30, 60 ou 90 jours)."""
    from .models import SLAPolicy

    policy = None
    if case.program_id and case.program.sla_policy_id:
        policy = case.program.sla_policy
    policy = policy or SLAPolicy.get_default()
    if policy is None:
        return 90
    return policy.remediation_days_for(case.severity)


def _pre_opened(case, data):
    from apps.audit.models import AuditAction, AuditLog, AuditResult

    opened = AuditLog.objects.filter(
        action=AuditAction.CASE_VIEWED,
        object_id=str(case.pk),
        result=AuditResult.SUCCESS,
    ).exists()
    return [] if opened else ["Dossier jamais ouvert"]


ADMISSIBILITY_CHECKLIST = [
    ("in_scope", "Le signalement relève du périmètre"),
    ("organization_identified", "L'organisation affectée est identifiée"),
    ("attachment_readable", "La pièce jointe est lisible"),
]


def _pre_admissible(case, data):
    missing = []
    if not case.organization_id:
        missing.append("Organisation affectée non identifiée")
    if not any(a.is_downloadable for a in case.attachments.all()):
        missing.append("Aucune pièce jointe lisible")
    if data is not None:
        for key, label in ADMISSIBILITY_CHECKLIST:
            if not data.get(key):
                missing.append(f"Checklist : « {label} » non cochée")
    return missing


def _pre_qualification(case, data):
    from apps.vulnerabilities.cvss import CVSSError, base_score

    missing = []
    if not case.cvss_vector:
        missing.append("Vecteur CVSS manquant")
    else:
        try:
            base_score(case.cvss_vector)
        except CVSSError:
            missing.append("Vecteur CVSS invalide")
    if not case.cwe_id:
        missing.append("CWE manquant")
    if not case.organization_id:
        missing.append("Organisation affectée non confirmée")
    return missing


def _pre_notify_vendor(case, data):
    missing = []
    if not case.organization_id:
        missing.append("Organisation affectée non renseignée")
    return missing


def _pre_remediation_plan(case, data):
    if data is None:
        return []
    missing = []
    if not (data.get("remediation_plan") or "").strip():
        missing.append("Plan de remédiation manquant")
    target = data.get("remediation_target_date")
    if not target:
        missing.append("Date cible manquante")
    else:
        limit = timezone.localdate() + timedelta(days=remediation_limit_days(case))
        if target > limit:
            missing.append(
                f"Date cible au-delà du délai de la sévérité ({limit:%d/%m/%Y} au plus tard)"
            )
        if target < timezone.localdate():
            missing.append("Date cible dans le passé")
    return missing


def _pre_fix(case, data):
    if data is None:
        return []
    missing = []
    if not (data.get("fix_description") or "").strip():
        missing.append("Description du correctif manquante")
    if not (data.get("fix_version") or "").strip() and not data.get("fix_deployed_on"):
        missing.append("Version ou date de déploiement du correctif manquante")
    return missing


def _pre_confirm_fix(case, data):
    if data is None:
        return []
    if not (data.get("verification_report") or "").strip():
        return ["Compte rendu de contre-vérification manquant"]
    return []


def _pre_submit_advisory(case, data):
    advisory = working_advisory(case)
    if advisory is None:
        return ["Aucun brouillon d'advisory"]
    missing = []
    if not (advisory.summary or "").strip():
        missing.append("Résumé public de l'advisory manquant")
    missing += advisory_sanitization_issues(advisory)
    return missing


def _pre_publish(case, data):
    from apps.disclosures.services import credit_for

    missing = []
    advisory = working_advisory(case)
    if advisory is None:
        missing.append("Aucun advisory à publier")
    elif (advisory.credit or "").strip() != credit_for(case):
        missing.append("Crédit non conforme au choix du chercheur")
    if case.bounty_stage not in BOUNTY_FINAL_STAGES:
        missing.append("Branche prime non terminée")
    if data is not None and not data.get("review_done"):
        missing.append("Relecture non confirmée")
    return missing


def _pre_close_without_advisory(case, data):
    if case.bounty_stage not in BOUNTY_FINAL_STAGES:
        return ["Branche prime non terminée"]
    return []


def advisory_editors_step(case):
    """Etape ou le brouillon d'advisory du dossier se redige, ou None.

    Etape 9 (correctif verifie, ou divulgation a echeance decidee) :
    l'analyste redige. Etape 10 (advisory en relecture) : le Coordinateur
    relit, modifie et valide -- ou redige si l'analyste a propose une
    cloture sans advisory.
    """
    if case.status == CaseStatus.FIX_VERIFIED or (
        case.deadline_disclosure_at and case.status in ESCALATION_STATES
    ):
        return "draft"
    if case.status == CaseStatus.ADVISORY_REVIEW:
        return "review"
    return None


def can_edit_case_advisory(case, user):
    """Le compte peut-il rediger ou modifier l'advisory de ce dossier ?

    Reserve au responsable de l'etape en cours : analyste a l'etape 9,
    Coordinateur a l'etape 10.
    """
    from .visibility import has_content_access

    step = advisory_editors_step(case)
    if step is None or getattr(user, "is_read_only", False):
        return False
    if not has_content_access(case, user) or case.reporter_id == user.pk:
        return False
    if must_claim(case, user):
        return False
    needed = Capability.DRAFT_ADVISORY if step == "draft" else Capability.PUBLISH_ADVISORY
    return user.has_capability(needed)


def _pre_propose_bounty(case, data):
    from apps.bounty.services import amount_outside_tier

    missing = []
    if case.reporter_id is None:
        missing.append("Aucun chercheur identifié")
    if data is not None and data.get("amount") is not None:
        if (
            amount_outside_tier(case, data["amount"])
            and not (data.get("justification") or "").strip()
        ):
            missing.append("Montant hors palier : justification écrite obligatoire")
    return missing


def reporter_can_reply(case):
    """Le declarant peut-il repondre sur la plateforme ?

    Un declarant anonyme -- rapport anonyme, ou soumis sans compte -- n'a
    aucun canal de reponse : son lien de suivi est en lecture seule. Lui
    demander des complements bloquerait le dossier sans issue.
    """
    return case.reporter_id is not None and not case.report.is_anonymous


def _pre_request_information(case, data):
    if not reporter_can_reply(case):
        return ["Déclarant anonyme : il ne peut pas répondre à une demande de compléments"]
    return []


def _pre_duplicate(case, data):
    if data is None:
        return []
    original = data.get("original")
    if original is None:
        return ["Dossier original manquant"]
    if original.pk == case.pk:
        return ["Un dossier ne peut pas être le doublon de lui-même"]
    if original.duplicate_of_id == case.pk:
        return ["Référence circulaire de doublon"]
    return []


def _pre_deadline_disclosure(case, data):
    missing = []
    if not case.escalated_at:
        missing.append("Dossier non escaladé")
    if case.deadline_disclosure_at:
        missing.append("Divulgation à échéance déjà décidée")
    notified = case.vendor_notified_at
    if notified is None or timezone.now() - notified < timedelta(
        days=DEADLINE_DISCLOSURE_DAYS
    ):
        missing.append(
            f"Moins de {DEADLINE_DISCLOSURE_DAYS} jours depuis la notification de l'organisation"
        )
    return missing


def _pre_escalate(case, data):
    return ["Dossier déjà escaladé"] if case.escalated_at else []


# ---------------------------------------------------------------------------
# Table des actions
# ---------------------------------------------------------------------------
PRIMARY = "primary"
SECONDARY = "secondary"

#: Pseudo-cibles resolues a l'execution.
RETURN_TO_ORIGIN = "__origin__"
RETURN_TO_PREVIOUS = "__previous__"
CONFIRMED_REJECTION = "__rejection__"


@dataclass(frozen=True)
class WorkflowAction:
    key: str
    label: str
    owner: str
    capability: str
    sources: tuple
    target: str | None
    kind: str = PRIMARY
    step: str = ""
    track: str = "case"  # "case" : statut du dossier ; "bounty" : statut de prime
    comment_required: bool = False
    #: Cle de l'action dont l'auteur ne peut pas executer celle-ci.
    four_eyes: str | None = None
    prerequisites: object = None
    reporter_only: bool = False
    #: Action secondaire reservee au responsable de l'etape en cours (seul a
    #: acceder au contenu du dossier) : complements, rejet, doublon, correctif
    #: insuffisant. Les actions principales le sont toujours.
    owner_only: bool = False
    fields: tuple = field(default_factory=tuple)

    def missing(self, case, data=None):
        return list(self.prerequisites(case, data)) if self.prerequisites else []


ACTIONS = [
    # -- Chemin principal ----------------------------------------------------
    WorkflowAction(
        "acknowledge",
        "Accuser réception",
        Owner.TRIAGER,
        Capability.TRIAGE_CASE,
        (CaseStatus.SUBMITTED,),
        CaseStatus.ACKNOWLEDGED,
        step="1",
        prerequisites=_pre_opened,
    ),
    WorkflowAction(
        "declare_admissible",
        "Déclarer recevable",
        Owner.TRIAGER,
        Capability.TRIAGE_CASE,
        (CaseStatus.ACKNOWLEDGED,),
        CaseStatus.IN_ANALYSIS,
        step="2",
        prerequisites=_pre_admissible,
        fields=tuple(key for key, _label in ADMISSIBILITY_CHECKLIST),
    ),
    WorkflowAction(
        "submit_qualification",
        "Soumettre la qualification",
        Owner.ANALYST,
        Capability.SET_SEVERITY,
        (CaseStatus.IN_ANALYSIS,),
        CaseStatus.VALIDATION_PENDING,
        step="3",
        prerequisites=_pre_qualification,
    ),
    WorkflowAction(
        "validate_qualification",
        "Valider la qualification",
        Owner.VALIDATOR,
        Capability.VALIDATE_SEVERITY,
        (CaseStatus.VALIDATION_PENDING,),
        CaseStatus.VALIDATED,
        step="4",
        comment_required=True,
        four_eyes="submit_qualification",
    ),
    WorkflowAction(
        "notify_vendor",
        "Transmettre à l'organisation",
        Owner.ANALYST,
        Capability.COORDINATE_VENDOR,
        (CaseStatus.VALIDATED,),
        CaseStatus.VENDOR_NOTIFIED,
        step="5",
        prerequisites=_pre_notify_vendor,
    ),
    WorkflowAction(
        "submit_remediation_plan",
        "Accepter et soumettre le plan de remédiation",
        Owner.VENDOR,
        Capability.MANAGE_REMEDIATION,
        (CaseStatus.VENDOR_NOTIFIED,),
        CaseStatus.REMEDIATION_IN_PROGRESS,
        step="6",
        prerequisites=_pre_remediation_plan,
        fields=("remediation_plan", "remediation_target_date"),
    ),
    WorkflowAction(
        "declare_fix",
        "Déclarer le correctif disponible",
        Owner.VENDOR,
        Capability.MANAGE_REMEDIATION,
        (CaseStatus.REMEDIATION_IN_PROGRESS,),
        CaseStatus.FIX_AVAILABLE,
        step="7",
        prerequisites=_pre_fix,
        fields=("fix_description", "fix_version", "fix_deployed_on"),
    ),
    WorkflowAction(
        "confirm_fix",
        "Confirmer le correctif",
        Owner.ANALYST,
        Capability.COORDINATE_VENDOR,
        (CaseStatus.FIX_AVAILABLE,),
        CaseStatus.FIX_VERIFIED,
        step="8",
        prerequisites=_pre_confirm_fix,
        fields=("verification_report",),
    ),
    WorkflowAction(
        "submit_advisory",
        "Soumettre l'advisory",
        Owner.ANALYST,
        Capability.DRAFT_ADVISORY,
        # VENDOR_NOTIFIED et REMEDIATION_IN_PROGRESS : seulement apres une
        # divulgation a echeance decidee par le Coordinateur (voir
        # `_source_allowed`).
        (
            CaseStatus.FIX_VERIFIED,
            CaseStatus.VENDOR_NOTIFIED,
            CaseStatus.REMEDIATION_IN_PROGRESS,
        ),
        CaseStatus.ADVISORY_REVIEW,
        step="9",
        prerequisites=_pre_submit_advisory,
    ),
    WorkflowAction(
        "publish_and_close",
        "Publier et clôturer",
        Owner.COORDINATOR,
        Capability.PUBLISH_ADVISORY,
        (CaseStatus.ADVISORY_REVIEW,),
        CaseStatus.CLOSED,
        step="10",
        comment_required=True,
        four_eyes="submit_advisory",
        prerequisites=_pre_publish,
        fields=("review_done",),
    ),
    # -- Branche Bug Bounty ------------------------------------------------------
    WorkflowAction(
        "propose_bounty",
        "Proposer la prime",
        Owner.ANALYST,
        Capability.PROPOSE_BOUNTY,
        (BountyStage.ELIGIBLE,),
        BountyStage.PROPOSED,
        step="B1",
        track="bounty",
        prerequisites=_pre_propose_bounty,
        fields=("amount", "justification"),
    ),
    WorkflowAction(
        "approve_bounty",
        "Approuver et créditer le Wallet",
        Owner.COORDINATOR,
        Capability.APPROVE_BOUNTY,
        (BountyStage.PROPOSED,),
        BountyStage.CREDITED,
        step="B2",
        track="bounty",
        comment_required=True,
        four_eyes="propose_bounty",
    ),
    # -- Sorties d'exception (actions secondaires) ------------------------------
    WorkflowAction(
        "request_information",
        "Demander des compléments",
        f"{Owner.TRIAGER}, {Owner.ANALYST}",
        Capability.REQUEST_INFORMATION,
        EARLY_STATES,
        CaseStatus.NEEDS_INFORMATION,
        kind=SECONDARY,
        comment_required=True,
        prerequisites=_pre_request_information,
        owner_only=True,
    ),
    WorkflowAction(
        "send_information",
        "Envoyer les compléments",
        Owner.REPORTER,
        Capability.SUBMIT_REPORT,
        (CaseStatus.NEEDS_INFORMATION,),
        RETURN_TO_ORIGIN,
        comment_required=True,
        reporter_only=True,
    ),
    WorkflowAction(
        "propose_rejection",
        "Proposer le rejet",
        f"{Owner.TRIAGER}, {Owner.ANALYST}",
        Capability.PROPOSE_REJECTION,
        EARLY_STATES + (CaseStatus.NEEDS_INFORMATION,),
        CaseStatus.REJECTION_PENDING,
        kind=SECONDARY,
        comment_required=True,
        owner_only=True,
    ),
    WorkflowAction(
        "propose_duplicate",
        "Marquer comme doublon",
        f"{Owner.TRIAGER}, {Owner.ANALYST}",
        Capability.PROPOSE_REJECTION,
        EARLY_STATES,
        CaseStatus.REJECTION_PENDING,
        kind=SECONDARY,
        comment_required=True,
        prerequisites=_pre_duplicate,
        fields=("original_case_id",),
        owner_only=True,
    ),
    WorkflowAction(
        "confirm_rejection",
        "Confirmer le rejet",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        (CaseStatus.REJECTION_PENDING,),
        CONFIRMED_REJECTION,
        comment_required=True,
        four_eyes="__into_current__",
    ),
    WorkflowAction(
        "return_rejection",
        "Renvoyer à l'étape d'origine",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        (CaseStatus.REJECTION_PENDING,),
        RETURN_TO_ORIGIN,
        kind=SECONDARY,
        comment_required=True,
    ),
    WorkflowAction(
        "return_to_author",
        "Renvoyer à l'auteur",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        (CaseStatus.VALIDATION_PENDING, CaseStatus.ADVISORY_REVIEW),
        RETURN_TO_PREVIOUS,
        kind=SECONDARY,
        comment_required=True,
    ),
    WorkflowAction(
        "return_bounty",
        "Renvoyer au proposeur",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        (BountyStage.PROPOSED,),
        BountyStage.ELIGIBLE,
        kind=SECONDARY,
        track="bounty",
        comment_required=True,
    ),
    WorkflowAction(
        "propose_closure",
        "Proposer une clôture sans advisory",
        Owner.ANALYST,
        Capability.DRAFT_ADVISORY,
        (CaseStatus.FIX_VERIFIED,),
        CaseStatus.ADVISORY_REVIEW,
        kind=SECONDARY,
        comment_required=True,
        owner_only=True,
    ),
    WorkflowAction(
        "close_without_advisory",
        "Clôturer sans publication",
        Owner.COORDINATOR,
        Capability.PUBLISH_ADVISORY,
        (CaseStatus.ADVISORY_REVIEW,),
        CaseStatus.CLOSED,
        kind=SECONDARY,
        comment_required=True,
        four_eyes="__into_current__",
        prerequisites=_pre_close_without_advisory,
        owner_only=True,
    ),
    WorkflowAction(
        "insufficient_fix",
        "Correctif insuffisant",
        Owner.ANALYST,
        Capability.COORDINATE_VENDOR,
        (CaseStatus.FIX_AVAILABLE,),
        CaseStatus.REMEDIATION_IN_PROGRESS,
        kind=SECONDARY,
        comment_required=True,
        owner_only=True,
    ),
    WorkflowAction(
        "escalate",
        "Escalader",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        ESCALATION_STATES,
        None,
        kind=SECONDARY,
        comment_required=True,
        prerequisites=_pre_escalate,
    ),
    WorkflowAction(
        "decide_deadline_disclosure",
        "Décider la divulgation à échéance",
        Owner.COORDINATOR,
        Capability.ARBITRATE_CASE,
        ESCALATION_STATES,
        None,
        kind=SECONDARY,
        comment_required=True,
        prerequisites=_pre_deadline_disclosure,
    ),
]

ACTIONS_BY_KEY = {action.key: action for action in ACTIONS}


def _build_transitions():
    table = {}
    for action in ACTIONS:
        if action.track != "case" or action.target is None:
            continue
        for source in action.sources:
            table.setdefault(source, [])
            if action.target not in table[source]:
                table[source].append(action.target)
    return table


#: Table declarative des transitions du dossier (statut -> cibles possibles).
#: Les pseudo-cibles (retour a l'origine, rejet confirme) sont resolues au
#: moment de l'execution a partir du dossier.
VDP_TRANSITIONS = _build_transitions()

#: Table des transitions de la branche prime.
BOUNTY_TRANSITIONS = {
    source: [action.target]
    for action in ACTIONS
    if action.track == "bounty"
    for source in action.sources
}


class TransitionNotAllowed(Exception):
    """Transition d'etat refusee par la machine a etats."""

    def __init__(self, message, missing=None):
        super().__init__(message)
        self.missing = list(missing or [])


class OutOfScope(TransitionNotAllowed):
    """Dossier hors du perimetre de l'utilisateur : la vue repond 404."""


def get_action(key):
    try:
        return ACTIONS_BY_KEY[key]
    except KeyError as exc:
        raise TransitionNotAllowed(f"Action inconnue : {key}.") from exc


def _current(case, action):
    return case.bounty_stage if action.track == "bounty" else case.status


def _source_allowed(case, action):
    if _current(case, action) not in action.sources:
        return False
    if action.key == "submit_advisory" and case.status != CaseStatus.FIX_VERIFIED:
        return bool(case.deadline_disclosure_at)
    return True


def resolve_target(case, action):
    """Statut d'arrivee effectif d'une action (pseudo-cibles resolues)."""
    if action.target == RETURN_TO_ORIGIN:
        return case.return_status or CaseStatus.ACKNOWLEDGED
    if action.target == CONFIRMED_REJECTION:
        return CaseStatus.DUPLICATE if case.duplicate_of_id else CaseStatus.REJECTED
    if action.target == RETURN_TO_PREVIOUS:
        entry = (
            case.status_history.filter(to_status=case.status).order_by("-created_at").first()
        )
        if entry and entry.from_status:
            return entry.from_status
        return CaseStatus.IN_ANALYSIS
    return action.target


def author_of(case, action):
    """Auteur de l'etape precedente, pour la regle des quatre yeux."""
    if action.four_eyes is None:
        return None
    if action.track == "bounty":
        bounty = getattr(case, "bounty", None)
        return bounty.proposed_by_id if bounty else None
    if action.four_eyes == "__into_current__":
        entry = (
            case.status_history.filter(to_status=case.status).order_by("-created_at").first()
        )
    else:
        source = ACTIONS_BY_KEY[action.four_eyes]
        entry = (
            case.status_history.filter(to_status=source.target).order_by("-created_at").first()
        )
    return entry.actor_id if entry else None


def is_in_scope(case, user):
    if user is None:
        return True
    return case.is_visible_to(user)


def check_transition(case, action, user=None, data=None):
    """Applique les six controles serveur d'une action de workflow.

    1. la transition existe pour le statut courant ;
    2. l'utilisateur possede la capacite requise ;
    3. le dossier est dans son perimetre (sinon OutOfScope -> 404) ;
    4. les pre-requis de l'etape sont remplis ;
    5. regle des quatre yeux : l'utilisateur n'est pas l'auteur de l'etape
       precedente pour les actions qui l'exigent ;
    6. (dans le service) le refus est audite hors transaction, l'application
       est atomique et auditee.

    `user=None` designe le systeme (taches planifiees) : capacite, perimetre
    et quatre yeux ne s'appliquent pas.
    """
    if isinstance(action, str):
        action = get_action(action)
    if not _source_allowed(case, action):
        raise TransitionNotAllowed(
            f"Action « {action.label} » impossible depuis l'état "
            f"{_current(case, action) or '—'}."
        )
    if user is not None:
        if not is_in_scope(case, user):
            raise OutOfScope("Dossier introuvable.")
        if getattr(user, "is_read_only", False):
            raise TransitionNotAllowed("Rôle en lecture seule.")
        if action.reporter_only:
            if case.reporter_id != user.pk:
                raise TransitionNotAllowed("Action réservée au déclarant du rapport.")
        elif not user.has_capability(action.capability):
            raise TransitionNotAllowed(
                f"Capacité requise pour cette action : {action.capability}."
            )
        elif not is_step_owner(case, action, user):
            raise TransitionNotAllowed(
                "Action réservée au responsable de l'étape en cours du dossier."
            )
    if (
        action.comment_required
        and data is not None
        and not (data.get("comment") or "").strip()
    ):
        raise TransitionNotAllowed("Un commentaire est obligatoire.", ["Commentaire manquant"])
    missing = action.missing(case, data)
    if missing:
        raise TransitionNotAllowed("Pré-requis manquants : " + " ; ".join(missing), missing)
    if user is not None and action.four_eyes:
        author_id = author_of(case, action)
        if author_id is not None and author_id == user.pk:
            raise TransitionNotAllowed(
                "Règle des quatre yeux : l'auteur de l'étape précédente ne peut pas la valider."
            )
    if user is not None and not action.reporter_only and must_claim(case, user):
        raise TransitionNotAllowed(
            f"{CLAIM_REQUIRED_MESSAGE} avant d'agir.", [CLAIM_REQUIRED_MESSAGE]
        )
    return True


# ---------------------------------------------------------------------------
# Responsables d'etape
# ---------------------------------------------------------------------------
def step_owners(case, action, ignore_claim=False):
    """Comptes responsables du bouton `action` sur ce dossier.

    Tous les comptes actifs portant la capacite et voyant le dossier, hors
    auteur de l'etape precedente (quatre yeux) ; si l'un d'eux a pris le
    dossier en charge, lui seul. `ignore_claim=True` rend le groupe entier
    (qui peut prendre en charge, a qui transferer).
    """
    from django.db.models import Q

    from apps.accounts.models import User
    from apps.accounts.roles import ROLE_CAPABILITIES, Role

    if action is None:
        return []
    if action.reporter_only:
        return [case.reporter] if case.reporter_id else []
    roles = [role for role, caps in ROLE_CAPABILITIES.items() if action.capability in caps]
    condition = Q(role__in=roles)
    if action.capability == Capability.VALIDATE_SEVERITY:
        condition |= Q(role=Role.CSIRT_ANALYST, is_senior_analyst=True)
    excluded = author_of(case, action) if action.four_eyes else None
    users = [
        user
        for user in User.objects.filter(condition, is_active=True)
        if user.pk != excluded and case.in_role_scope(user)
    ]
    if action.kind != PRIMARY and action.owner_only:
        # Exception reservee au responsable de l'etape en cours.
        owners = current_owner_ids(case)
        return [user for user in users if user.pk in owners]
    if not ignore_claim:
        claimed = claimed_ids(case)
        mine = [user for user in users if user.pk in claimed]
        if mine:
            return mine
    return users


def claimed_ids(case):
    """Comptes ayant pris le dossier en charge (au plus un par role)."""
    return set(case.assignments.filter(is_active=True).values_list("user_id", flat=True))


def claim_action(case):
    """Bouton principal dont le responsable peut prendre le dossier en charge."""
    action = primary_action(case)
    if action is None or action.reporter_only:
        return None
    return action


def claim_pools(case):
    """(action, groupe de responsables) pour chaque action en cours.

    Dossier, branche prime et escalade peuvent attendre des roles
    differents en meme temps : chacun se prend en charge separement.
    """
    return [
        (action, step_owners(case, action, ignore_claim=True))
        for action in current_actions(case)
        if not action.reporter_only
    ]


def claim_holder(case, action=None):
    """Compte ayant pris en charge l'action (par defaut le bouton principal)."""
    action = action or claim_action(case)
    if action is None:
        return None
    claimed = claimed_ids(case)
    for user in step_owners(case, action, ignore_claim=True):
        if user.pk in claimed:
            return user
    return None


def user_pools(case, user):
    """Groupes de responsables auxquels `user` appartient a l'etape en cours."""
    return [(action, pool) for action, pool in claim_pools(case) if user in pool]


def has_claim(case, user):
    """`user` a-t-il pris en charge une etape en cours de ce dossier ?"""
    return bool(user_pools(case, user)) and user.pk in claimed_ids(case)


def can_claim(case, user):
    """`user` peut-il prendre en charge une etape en cours restee libre ?"""
    if getattr(user, "is_read_only", False) or has_claim(case, user):
        return False
    return any(claim_holder(case, action) is None for action, _pool in user_pools(case, user))


def must_claim(case, user):
    """Toute action d'un compte metier exige d'avoir pris le dossier en charge."""
    if user is None or case.reporter_id == user.pk:
        return False
    return not has_claim(case, user)


CLAIM_REQUIRED_MESSAGE = "Prenez d'abord le dossier en charge"


def statuses_owned_by(user):
    """(statuts, statuts de prime) ou un bouton principal revient a `user`.

    Pre-filtre large (tout statut ou l'une de ses actions principales peut
    s'appliquer) : le controle exact reste celui de current_owner_ids.
    """
    statuses, stages = set(), set()
    for action in ACTIONS:
        if action.kind != PRIMARY or action.target is None or action.reporter_only:
            continue
        if user.has_capability(action.capability):
            (stages if action.track == "bounty" else statuses).update(action.sources)
    if user.has_capability(ACTIONS_BY_KEY["decide_deadline_disclosure"].capability):
        statuses.update(ESCALATION_STATES)
    return statuses, stages


def escalation_action(case):
    """Decision attendue du Coordinateur sur un dossier escalade.

    Un depassement aux etapes 6 ou 7 escalade le dossier : le Coordinateur en
    devient responsable, jusqu'a sa decision de divulgation a echeance.
    """
    if (
        case.escalated_at
        and not case.deadline_disclosure_at
        and case.status in ESCALATION_STATES
    ):
        return ACTIONS_BY_KEY["decide_deadline_disclosure"]
    return None


def current_actions(case):
    """Actions attendues a l'etape en cours : dossier, branche prime, escalade."""
    candidates = (primary_action(case), bounty_action(case), escalation_action(case))
    return [action for action in candidates if action]


def current_owner_ids(case):
    """Identifiants des responsables de l'etape en cours du dossier."""
    ids = set()
    for action in current_actions(case):
        ids.update(user.pk for user in step_owners(case, action))
    return ids


def is_step_owner(case, action, user):
    """`user` est-il responsable de l'etape que l'action fait avancer ?

    Bouton principal : proprietaire de ce bouton. Action secondaire marquee
    `owner_only` : responsable de l'etape en cours. Les autres actions
    secondaires (arbitrage, escalade) restent ouvertes a leur capacite.
    """
    if action.reporter_only:
        return case.reporter_id == user.pk
    if action.kind == PRIMARY:
        if action.four_eyes and author_of(case, action) == user.pk:
            # Le refus « quatre yeux » garde son propre message plus loin.
            return True
        return user.pk in {owner.pk for owner in step_owners(case, action)}
    if action.owner_only:
        return user.pk in current_owner_ids(case)
    return True


def available_actions(case, kind=None):
    """Actions applicables au statut courant (sans controle d'utilisateur)."""
    result = []
    for action in ACTIONS:
        if kind is not None and action.kind != kind:
            continue
        if _source_allowed(case, action):
            result.append(action)
    return result


def primary_action(case):
    """Bouton principal de l'etape courante (chemin principal).

    Apres une divulgation a echeance, l'etape attendue n'est plus le
    correctif de l'organisation mais l'advisory de l'analyste.
    """
    actions = [a for a in available_actions(case, kind=PRIMARY) if a.track == "case"]
    if case.deadline_disclosure_at:
        for action in actions:
            if action.key == "submit_advisory":
                return action
    return actions[0] if actions else None


def bounty_action(case):
    for action in available_actions(case, kind=PRIMARY):
        if action.track == "bounty":
            return action
    return None


def allowed_targets(current_status, workflow=None):
    """Statuts atteignables depuis `current_status` (table declarative)."""
    return list(VDP_TRANSITIONS.get(current_status, []))


def step_number(status):
    try:
        return MAIN_PATH.index(status)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Kanban et statut simplifie
# ---------------------------------------------------------------------------
KANBAN_COLUMNS = [
    (
        "RECEPTION",
        "Réception",
        [CaseStatus.SUBMITTED, CaseStatus.ACKNOWLEDGED, CaseStatus.NEEDS_INFORMATION],
    ),
    (
        "ANALYSIS",
        "Analyse",
        [CaseStatus.IN_ANALYSIS, CaseStatus.VALIDATION_PENDING, CaseStatus.REJECTION_PENDING],
    ),
    ("VALIDATED", "Validé", [CaseStatus.VALIDATED]),
    (
        "REMEDIATION",
        "Remédiation",
        [
            CaseStatus.VENDOR_NOTIFIED,
            CaseStatus.REMEDIATION_IN_PROGRESS,
            CaseStatus.FIX_AVAILABLE,
        ],
    ),
    ("PUBLICATION", "Publication", [CaseStatus.FIX_VERIFIED, CaseStatus.ADVISORY_REVIEW]),
    ("CLOSED", "Clos", [CaseStatus.CLOSED, CaseStatus.REJECTED, CaseStatus.DUPLICATE]),
]


def kanban_column_for(status):
    for key, _label, states in KANBAN_COLUMNS:
        if status in states:
            return key
    return "CLOSED"


#: Statut simplifie a 5 paliers montre au declarant (compte ou lien de
#: suivi) : il ne revele rien de l'avancement interne -- ni file d'attente,
#: ni rejet seulement propose, ni raison exacte d'une cloture.
PUBLIC_STATUS_BUCKETS = [
    ("RECEIVED", "Reçu", [CaseStatus.SUBMITTED, CaseStatus.ACKNOWLEDGED]),
    (
        "ANALYSIS",
        "En analyse",
        [
            CaseStatus.IN_ANALYSIS,
            CaseStatus.VALIDATION_PENDING,
            CaseStatus.NEEDS_INFORMATION,
            CaseStatus.REJECTION_PENDING,
        ],
    ),
    ("VALIDATED", "Validé", [CaseStatus.VALIDATED]),
    (
        "IN_PROGRESS",
        "En correction",
        [
            CaseStatus.VENDOR_NOTIFIED,
            CaseStatus.REMEDIATION_IN_PROGRESS,
            CaseStatus.FIX_AVAILABLE,
            CaseStatus.FIX_VERIFIED,
            CaseStatus.ADVISORY_REVIEW,
        ],
    ),
    ("RESOLVED", "Publié", [CaseStatus.CLOSED]),
    ("DISMISSED", "Clôturé sans suite", list(DISMISSED_STATES)),
]

#: Les cinq paliers de progression, dans l'ordre (hors cloture sans suite).
PUBLIC_STATUS_STEPS = [(key, label) for key, label, _ in PUBLIC_STATUS_BUCKETS[:5]]


def public_status_bucket(status, published=True):
    """(cle, libelle) simplifies pour le declarant.

    `published=False` : dossier clos sans publication d'advisory, affiche
    « Clôturé » plutot que « Publié ».
    """
    for key, label, states in PUBLIC_STATUS_BUCKETS:
        if status in states:
            if key == "RESOLVED" and not published:
                return key, "Clôturé"
            return key, label
    return "ANALYSIS", "En analyse"


def public_status_of(case):
    return public_status_bucket(case.status, published=case.is_published)
