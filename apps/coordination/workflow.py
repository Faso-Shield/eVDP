"""Workflow eVDP v2 - conforme a SPEC-eVDP-2026-V2.

Principe : chaque etape a UN proprietaire et UN bouton pour avancer. Les
sorties d'exception (complements, rejet, doublon, renvoi, correctif
insuffisant) sont declarees a part et n'apparaissent jamais comme bouton
principal.

`check_transition()` est le seul point de decision. Il verifie, dans l'ordre :

  1. la transition existe pour le statut courant ;
  2. le dossier est dans le perimetre de l'utilisateur (sinon 404 cote vue) ;
  3. l'utilisateur possede la capacite requise ;
  4. les pre-requis de l'etape sont remplis ;
  5. la regle des quatre yeux (l'acteur differe de l'auteur de l'etape
     precedente) pour les transitions marquees `four_eyes` ;
  6. le commentaire obligatoire.

Le refus est audite HORS transaction par l'appelant ; l'application est
atomique et auditee (voir services.transition_case).

La branche Bug Bounty avance en parallele sur un champ distinct
(`Case.bounty_status`) : voir BOUNTY_TRANSITIONS et apps.bounty.services.
"""

from dataclasses import dataclass, field

from django.db import models

from apps.accounts.roles import ROLE_CAPABILITIES, Capability, Role, role_label


# =============================================================================
# Statuts
# =============================================================================
class CaseStatus(models.TextChoices):
    # Chemin principal (11 etapes)
    SUBMITTED = "SUBMITTED", "Soumis"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accusé de réception"
    IN_ANALYSIS = "IN_ANALYSIS", "En analyse"
    VALIDATION_PENDING = "VALIDATION_PENDING", "Qualification à valider"
    VALIDATED = "VALIDATED", "Validé"
    VENDOR_NOTIFIED = "VENDOR_NOTIFIED", "Organisation notifiée"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS", "Remédiation en cours"
    FIX_AVAILABLE = "FIX_AVAILABLE", "Correctif disponible"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    ADVISORY_REVIEW = "ADVISORY_REVIEW", "Advisory en relecture"
    CLOSED = "CLOSED", "Clos"
    # Exceptions
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


class CaseBountyStatus(models.TextChoices):
    """Statut de la branche prime, distinct du statut du dossier."""

    UNDETERMINED = "UNDETERMINED", "Non déterminé"
    NOT_ELIGIBLE = "NOT_ELIGIBLE", "Non éligible"
    BOUNTY_ELIGIBLE = "BOUNTY_ELIGIBLE", "Éligible à une prime"
    BOUNTY_PROPOSED = "BOUNTY_PROPOSED", "Prime proposée"
    BOUNTY_CREDITED = "BOUNTY_CREDITED", "Prime créditée"


#: Etats terminaux : plus aucune transition sortante.
TERMINAL_STATES = frozenset({CaseStatus.CLOSED, CaseStatus.REJECTED, CaseStatus.DUPLICATE})

#: Etats consideres comme "resolus sans suite".
DISMISSED_STATES = frozenset({CaseStatus.REJECTED, CaseStatus.DUPLICATE})

#: Etats d'exception : le dossier y attend une decision hors chemin principal.
EXCEPTION_STATES = frozenset({CaseStatus.NEEDS_INFORMATION, CaseStatus.REJECTION_PENDING})

#: Etats a partir desquels l'organisation affectee peut voir le dossier
#: (etape 5 et suivantes). Jamais avant que le CSIRT ne l'ait explicitement
#: engagee : pendant le triage, le declarant doit rester protege d'une
#: reaction prematuree de l'organisation sur un signalement non valide.
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

#: Statut simplifie montre au declarant (aucune fuite de l'avancement interne).
#: Cinq paliers : Recu, En analyse, Valide, En correction, Publie.
RESEARCHER_VIEW = {
    CaseStatus.SUBMITTED: ("RECEIVED", "Reçu"),
    CaseStatus.ACKNOWLEDGED: ("RECEIVED", "Reçu"),
    CaseStatus.NEEDS_INFORMATION: ("NEEDS_INFORMATION", "Compléments demandés"),
    CaseStatus.IN_ANALYSIS: ("ANALYSIS", "En analyse"),
    CaseStatus.VALIDATION_PENDING: ("ANALYSIS", "En analyse"),
    CaseStatus.REJECTION_PENDING: ("ANALYSIS", "En analyse"),
    CaseStatus.VALIDATED: ("VALIDATED", "Validé"),
    CaseStatus.VENDOR_NOTIFIED: ("IN_PROGRESS", "En correction"),
    CaseStatus.REMEDIATION_IN_PROGRESS: ("IN_PROGRESS", "En correction"),
    CaseStatus.FIX_AVAILABLE: ("IN_PROGRESS", "En correction"),
    CaseStatus.FIX_VERIFIED: ("IN_PROGRESS", "En correction"),
    CaseStatus.ADVISORY_REVIEW: ("IN_PROGRESS", "En correction"),
    CaseStatus.CLOSED: ("RESOLVED", "Publié"),
    CaseStatus.REJECTED: ("DISMISSED", "Clos (non retenu)"),
    CaseStatus.DUPLICATE: ("DISMISSED", "Clos (non retenu)"),
}


def public_status_bucket(status):
    """(cle, libelle) simplifies pour le declarant et la page de suivi."""
    return RESEARCHER_VIEW.get(status, ("ANALYSIS", "En analyse"))


# =============================================================================
# Transitions
# =============================================================================
@dataclass(frozen=True)
class Transition:
    action: str  # identifiant stable (audit, API)
    label: str  # texte du bouton
    source: str
    target: str | None  # None = retour a l'etape d'origine
    capability: str
    primary: bool = True  # True = LE bouton de l'etape ; False = exception
    four_eyes: bool = False  # l'acteur doit differer de l'auteur de l'etape precedente
    comment_required: bool = False
    requires: tuple = field(default_factory=tuple)  # cles de PREREQUISITES


S = CaseStatus
Cap = Capability

VDP_TRANSITIONS = (
    # ------------------------------------------------ chemin principal (1 bouton / etape)
    Transition(
        "acknowledge", "Accuser réception", S.SUBMITTED, S.ACKNOWLEDGED,
        Cap.TRIAGE_CASE, requires=("opened_by_actor",),
    ),
    Transition(
        "declare_admissible", "Déclarer recevable", S.ACKNOWLEDGED, S.IN_ANALYSIS,
        Cap.TRIAGE_CASE, requires=("admissibility_checklist",),
    ),
    Transition(
        "submit_qualification", "Soumettre la qualification", S.IN_ANALYSIS,
        S.VALIDATION_PENDING, Cap.SET_SEVERITY,
        requires=("cvss_vector", "cwe", "affected_organization"),
    ),
    Transition(
        "validate_qualification", "Valider la qualification", S.VALIDATION_PENDING,
        S.VALIDATED, Cap.VALIDATE_SEVERITY, four_eyes=True, comment_required=True,
        requires=("cvss_vector", "not_qualifier"),
    ),
    Transition(
        "notify_vendor", "Transmettre à l'organisation", S.VALIDATED, S.VENDOR_NOTIFIED,
        Cap.NOTIFY_VENDOR, requires=("affected_organization", "vendor_version"),
    ),
    Transition(
        "submit_remediation_plan", "Accepter et soumettre le plan de remédiation",
        S.VENDOR_NOTIFIED, S.REMEDIATION_IN_PROGRESS, Cap.MANAGE_REMEDIATION,
        requires=("remediation_plan", "remediation_due_date"),
    ),
    Transition(
        "declare_fix", "Déclarer le correctif disponible", S.REMEDIATION_IN_PROGRESS,
        S.FIX_AVAILABLE, Cap.MANAGE_REMEDIATION, requires=("fix_description",),
    ),
    Transition(
        "verify_fix", "Confirmer le correctif", S.FIX_AVAILABLE, S.FIX_VERIFIED,
        Cap.VERIFY_FIX, requires=("verification_report",),
    ),
    Transition(
        "submit_advisory", "Soumettre l'advisory", S.FIX_VERIFIED, S.ADVISORY_REVIEW,
        Cap.DRAFT_ADVISORY, requires=("advisory_draft_sanitized",),
    ),
    Transition(
        "publish_and_close", "Publier et clôturer", S.ADVISORY_REVIEW, S.CLOSED,
        Cap.PUBLISH_ADVISORY, four_eyes=True, comment_required=True,
        requires=("advisory_draft_sanitized", "bounty_settled"),
    ),
    # ------------------------------------------------ exceptions (jamais bouton principal)
    *(
        Transition(
            "request_information", "Demander des compléments", src, S.NEEDS_INFORMATION,
            Cap.REQUEST_INFORMATION, primary=False, comment_required=True,
        )
        for src in (S.SUBMITTED, S.ACKNOWLEDGED, S.IN_ANALYSIS)
    ),
    # Seul bouton du statut d'attente : il appartient au declarant.
    Transition(
        "provide_information", "Envoyer les compléments", S.NEEDS_INFORMATION, None,
        Cap.PROVIDE_INFORMATION, comment_required=True, requires=("reporter_is_owner",),
    ),
    *(
        Transition(
            "propose_rejection", "Proposer le rejet", src, S.REJECTION_PENDING,
            Cap.PROPOSE_REJECTION, primary=False, comment_required=True,
        )
        for src in (S.SUBMITTED, S.ACKNOWLEDGED, S.IN_ANALYSIS, S.NEEDS_INFORMATION)
    ),
    *(
        Transition(
            "propose_duplicate", "Marquer comme doublon", src, S.REJECTION_PENDING,
            Cap.PROPOSE_REJECTION, primary=False, comment_required=True,
            requires=("duplicate_of",),
        )
        for src in (S.SUBMITTED, S.ACKNOWLEDGED, S.IN_ANALYSIS, S.NEEDS_INFORMATION)
    ),
    # Motif doublon (dossier original renseigne) -> DUPLICATE, sinon REJECTED :
    # la cible est resolue par resolve_target().
    Transition(
        "confirm_rejection", "Confirmer le rejet", S.REJECTION_PENDING, S.REJECTED,
        Cap.CONFIRM_REJECTION, four_eyes=True, comment_required=True,
    ),
    Transition(
        "cancel_rejection", "Renvoyer à l'étape d'origine", S.REJECTION_PENDING, None,
        Cap.SEND_BACK, primary=False, comment_required=True,
    ),
    Transition(
        "send_back_qualification", "Renvoyer à l'analyste", S.VALIDATION_PENDING,
        S.IN_ANALYSIS, Cap.SEND_BACK, primary=False, comment_required=True,
    ),
    Transition(
        "send_back_advisory", "Renvoyer à l'analyste", S.ADVISORY_REVIEW, S.FIX_VERIFIED,
        Cap.SEND_BACK, primary=False, comment_required=True,
    ),
    Transition(
        "reject_fix", "Correctif insuffisant", S.FIX_AVAILABLE, S.REMEDIATION_IN_PROGRESS,
        Cap.VERIFY_FIX, primary=False, comment_required=True,
    ),
)  # fmt: skip

B = CaseBountyStatus


@dataclass(frozen=True)
class BountyTransition:
    action: str
    label: str
    source: str
    target: str
    capability: str
    four_eyes: bool = False
    comment_required: bool = False


#: Branche Bug Bounty, ouverte en parallele des VALIDATED pour un programme
#: eligible. Le statut de prime avance independamment du statut du dossier.
BOUNTY_TRANSITIONS = (
    BountyTransition(
        "propose_bounty", "Proposer la prime", B.BOUNTY_ELIGIBLE, B.BOUNTY_PROPOSED,
        Cap.PROPOSE_BOUNTY,
    ),
    BountyTransition(
        "approve_bounty", "Approuver et créditer le Wallet", B.BOUNTY_PROPOSED,
        B.BOUNTY_CREDITED, Cap.APPROVE_BOUNTY, four_eyes=True, comment_required=True,
    ),
    BountyTransition(
        "send_back_bounty", "Renvoyer", B.BOUNTY_PROPOSED, B.BOUNTY_ELIGIBLE,
        Cap.SEND_BACK, comment_required=True,
    ),
)  # fmt: skip

#: Delai de remediation (jours) selon la severite validee (valeurs par defaut ;
#: la politique SLA du programme fait foi).
REMEDIATION_DAYS = {"CRITICAL": 30, "HIGH": 60, "MEDIUM": 90, "LOW": 90, "INFO": 90}

#: Delai (jours) sans reponse du declarant avant proposition automatique de rejet.
INFORMATION_TIMEOUT_DAYS = 30

#: Actions secondaires hors machine a etats (pas de changement de statut).
ESCALATION_STATES = frozenset({S.VENDOR_NOTIFIED, S.REMEDIATION_IN_PROGRESS})


# =============================================================================
# Pre-requis : chaque cle -> fonction (case, actor) -> bool
# =============================================================================
def _opened_by_actor(case, actor):
    from apps.audit.models import AuditAction, AuditLog, AuditResult

    return AuditLog.objects.filter(
        action=AuditAction.CASE_VIEWED,
        actor=actor,
        object_id=str(case.pk),
        result=AuditResult.SUCCESS,
    ).exists()


def _advisory_sanitized(case, actor):
    from apps.disclosures.services import sanitization_issues

    advisory = case.current_advisory()
    return advisory is not None and not sanitization_issues(advisory)


PREREQUISITES = {
    "opened_by_actor": _opened_by_actor,
    "admissibility_checklist": lambda c, u: c.admissibility_complete,
    "cvss_vector": lambda c, u: bool(c.cvss_vector) and c.cvss_set_by_id is not None,
    "not_qualifier": lambda c, u: u is None or c.cvss_set_by_id != u.pk,
    "cwe": lambda c, u: c.cwe_id is not None,
    "affected_organization": lambda c, u: c.organization_id is not None,
    "vendor_version": lambda c, u: bool(c.vendor_summary.strip()),
    "remediation_plan": lambda c, u: bool(c.remediation_plan.strip()),
    "remediation_due_date": lambda c, u: c.remediation_due_date is not None,
    "fix_description": lambda c, u: bool(c.fix_description.strip()),
    "verification_report": lambda c, u: bool(c.fix_verification_notes.strip()),
    "advisory_draft_sanitized": _advisory_sanitized,
    "bounty_settled": lambda c, u: c.bounty_status
    in (CaseBountyStatus.NOT_ELIGIBLE, CaseBountyStatus.BOUNTY_CREDITED),
    "reporter_is_owner": lambda c, u: u is not None and c.reporter_id == u.pk,
    "duplicate_of": lambda c, u: c.duplicate_of_id is not None,
}

PREREQUISITE_LABELS = {
    "opened_by_actor": "Ouvrir le dossier",
    "admissibility_checklist": "Checklist de recevabilité incomplète",
    "cvss_vector": "Vecteur CVSS manquant (saisi par un analyste)",
    "not_qualifier": "Le valideur doit différer de l'auteur de la qualification",
    "cwe": "CWE manquante",
    "affected_organization": "Organisation affectée non confirmée",
    "vendor_version": "Version « organisation » du rapport manquante",
    "remediation_plan": "Plan de remédiation manquant",
    "remediation_due_date": "Date cible du correctif manquante",
    "fix_description": "Description du correctif manquante",
    "verification_report": "Compte rendu de contre-vérification manquant",
    "advisory_draft_sanitized": "Brouillon d'advisory assaini manquant",
    "bounty_settled": "Prime ni créditée ni déclarée non éligible",
    "reporter_is_owner": "Réservé à l'auteur du rapport",
    "duplicate_of": "Dossier original non renseigné",
}


# =============================================================================
# Decision
# =============================================================================
class TransitionNotAllowed(Exception):
    """Transition refusee. `code` distingue la cause (404 pour not_found)."""

    def __init__(self, message="", code="invalid_transition", missing=None):
        super().__init__(message or code)
        self.code = code
        self.missing = list(missing or [])


def transitions_from(status):
    return [t for t in VDP_TRANSITIONS if t.source == status]


def find_transition(status, action):
    return next(
        (t for t in VDP_TRANSITIONS if t.source == status and t.action == action), None
    )


def primary_transition(status):
    """Le bouton unique de l'etape (None pour un statut terminal)."""
    primaries = [t for t in VDP_TRANSITIONS if t.source == status and t.primary]
    if len(primaries) > 1:  # pragma: no cover - invariant verifie au chargement
        raise AssertionError(f"{status} a plusieurs boutons principaux")
    return primaries[0] if primaries else None


def secondary_transitions(status):
    return [t for t in VDP_TRANSITIONS if t.source == status and not t.primary]


def missing_prerequisites(transition, case, actor):
    return [
        PREREQUISITE_LABELS[key]
        for key in transition.requires
        if not PREREQUISITES[key](case, actor)
    ]


def previous_step_author_id(case):
    """Auteur de la transition qui a amene le dossier dans son statut courant."""
    last = case.status_history.filter(to_status=case.status).order_by("-created_at").first()
    return last.actor_id if last is not None else None


def check_transition(case, actor, action, comment=""):
    """Seul point de decision. Leve TransitionNotAllowed ou rend la transition.

    A appeler HORS transaction : en cas de refus, l'appelant journalise
    durablement le refus puis repond 403/404.
    """
    transition = find_transition(case.status, action)
    if transition is None:
        raise TransitionNotAllowed(
            f"Action « {action} » impossible depuis le statut {case.get_status_display()}.",
            code="invalid_transition",
        )
    if actor is None or not case.is_visible_to(actor):
        raise TransitionNotAllowed("Dossier introuvable.", code="not_found")
    if not actor.has_capability(transition.capability):
        raise TransitionNotAllowed(
            f"Capacité requise pour cette action : {transition.capability}.",
            code="forbidden",
        )
    if getattr(actor, "is_read_only", False):
        raise TransitionNotAllowed("Rôle en lecture seule.", code="forbidden")
    missing = missing_prerequisites(transition, case, actor)
    if missing:
        raise TransitionNotAllowed(
            "Pré-requis manquants : " + " ; ".join(missing) + ".",
            code="prerequisites",
            missing=missing,
        )
    if transition.four_eyes and previous_step_author_id(case) == actor.pk:
        raise TransitionNotAllowed(
            "Règle des quatre yeux : le valideur doit différer de l'auteur de l'étape "
            "précédente.",
            code="four_eyes",
        )
    if transition.comment_required and not (comment or "").strip():
        raise TransitionNotAllowed("Un commentaire est obligatoire.", code="comment_required")
    return transition


def resolve_target(case, transition):
    """Cible effective : retour a l'etape d'origine, ou doublon confirme."""
    if transition.action == "confirm_rejection" and case.duplicate_of_id:
        return CaseStatus.DUPLICATE
    if transition.target is not None:
        return transition.target
    return case.status_before_exception or CaseStatus.SUBMITTED


def owners_of(capability):
    """Roles proprietaires d'une capacite (pour « En attente de : <role> »)."""
    roles = [role for role, caps in ROLE_CAPABILITIES.items() if capability in caps]
    if capability == Capability.VALIDATE_SEVERITY:
        roles.append("SENIOR_ANALYST")
    return roles


def owner_labels(capability):
    labels = []
    for role in owners_of(capability):
        labels.append("Analyste senior" if role == "SENIOR_ANALYST" else role_label(role))
    return labels


def button_for(case, actor):
    """Ce que l'interface affiche : un seul bouton, actif ou grise avec la
    liste des pre-requis manquants, ou « En attente de : <role> »."""
    transition = primary_transition(case.status)
    if transition is None:
        return {"kind": "none"}
    if (
        actor is None
        or not actor.has_capability(transition.capability)
        or getattr(actor, "is_read_only", False)
    ):
        return {"kind": "waiting", "waiting_for": owner_labels(transition.capability)}
    missing = missing_prerequisites(transition, case, actor)
    if transition.four_eyes and previous_step_author_id(case) == actor.pk:
        missing.append("Règle des quatre yeux : une autre personne doit valider")
    return {
        "kind": "button",
        "action": transition.action,
        "label": transition.label,
        "enabled": not missing,
        "missing": missing,
        "comment_required": transition.comment_required,
    }


def secondary_actions_for(case, actor):
    """Actions d'exception proposees a l'utilisateur (menu secondaire)."""
    if actor is None or getattr(actor, "is_read_only", False):
        return []
    return [
        t for t in secondary_transitions(case.status) if actor.has_capability(t.capability)
    ]


# =============================================================================
# Kanban
# =============================================================================
KANBAN_COLUMNS = [
    ("SUBMITTED", "Réception", [S.SUBMITTED, S.ACKNOWLEDGED]),
    (
        "ANALYSIS",
        "Analyse",
        [S.IN_ANALYSIS, S.NEEDS_INFORMATION, S.VALIDATION_PENDING, S.REJECTION_PENDING],
    ),
    ("VALIDATED", "Validé", [S.VALIDATED, S.VENDOR_NOTIFIED]),
    ("REMEDIATION", "Remédiation", [S.REMEDIATION_IN_PROGRESS, S.FIX_AVAILABLE]),
    ("DISCLOSURE", "Publication", [S.FIX_VERIFIED, S.ADVISORY_REVIEW]),
    ("CLOSED", "Clos", [S.CLOSED, S.REJECTED, S.DUPLICATE]),
]


def kanban_column_for(status):
    for key, _label, states in KANBAN_COLUMNS:
        if status in states:
            return key
    return "CLOSED"


# Invariant verifie au chargement : un seul bouton principal par statut.
for _status in CaseStatus.values:
    primary_transition(_status)

__all__ = [
    "BOUNTY_TRANSITIONS",
    "CaseBountyStatus",
    "CaseStatus",
    "DISMISSED_STATES",
    "EXCEPTION_STATES",
    "KANBAN_COLUMNS",
    "ORG_VISIBLE_STATES",
    "PREREQUISITES",
    "RESEARCHER_VIEW",
    "Role",
    "TERMINAL_STATES",
    "Transition",
    "TransitionNotAllowed",
    "VDP_TRANSITIONS",
    "button_for",
    "check_transition",
    "find_transition",
    "primary_transition",
    "public_status_bucket",
    "resolve_target",
    "secondary_actions_for",
]
