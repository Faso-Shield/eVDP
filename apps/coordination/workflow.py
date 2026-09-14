"""Machine a etats du traitement des cases.

Deux workflows coexistent sur un moteur unique :

  * CVD (VDP)  : signalement -> triage -> coordination -> correction -> publication
  * Bug Bounty : programme -> soumission -> triage -> severite -> recompense
                 -> remediation -> divulgation

Toute transition non declaree ici est interdite. Chaque transition peut exiger
une capacite RBAC particuliere (ex. approuver une recompense).
"""

from django.db import models

from apps.accounts.roles import Capability


class CaseStatus(models.TextChoices):
    DRAFT = "DRAFT", "Brouillon"
    SUBMITTED = "SUBMITTED", "Soumis"
    RECEIVED = "RECEIVED", "Reçu"
    TRIAGE = "TRIAGE", "En triage"
    NEEDS_INFORMATION = "NEEDS_INFORMATION", "Informations demandées"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accusé de réception"
    VALIDATED = "VALIDATED", "Validé"
    SEVERITY_ASSIGNED = "SEVERITY_ASSIGNED", "Sévérité attribuée"
    BOUNTY_REVIEW = "BOUNTY_REVIEW", "Revue de récompense"
    REWARD_APPROVED = "REWARD_APPROVED", "Récompense approuvée"
    DUPLICATE = "DUPLICATE", "Doublon"
    REJECTED = "REJECTED", "Rejeté"
    OUT_OF_SCOPE = "OUT_OF_SCOPE", "Hors périmètre"
    NOT_APPLICABLE = "NOT_APPLICABLE", "Non applicable"
    INFORMATIVE = "INFORMATIVE", "Informatif"
    IN_PROGRESS = "IN_PROGRESS", "En cours de traitement"
    VENDOR_CONTACTED = "VENDOR_CONTACTED", "Organisation contactée"
    VENDOR_ACKNOWLEDGED = "VENDOR_ACKNOWLEDGED", "Organisation a accusé réception"
    REMEDIATION = "REMEDIATION", "Remédiation en cours"
    FIX_AVAILABLE = "FIX_AVAILABLE", "Correctif disponible"
    VERIFICATION = "VERIFICATION", "Vérification du correctif"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    DISCLOSURE_SCHEDULED = "DISCLOSURE_SCHEDULED", "Divulgation planifiée"
    PUBLISHED = "PUBLISHED", "Publié"
    CLOSED = "CLOSED", "Clos"

    @classmethod
    def validated_states(cls):
        """Etats attestant qu'un rapport a ete reconnu comme valide."""
        return [
            cls.VALIDATED,
            cls.SEVERITY_ASSIGNED,
            cls.BOUNTY_REVIEW,
            cls.REWARD_APPROVED,
            cls.IN_PROGRESS,
            cls.VENDOR_CONTACTED,
            cls.VENDOR_ACKNOWLEDGED,
            cls.REMEDIATION,
            cls.FIX_AVAILABLE,
            cls.VERIFICATION,
            cls.FIX_VERIFIED,
            cls.DISCLOSURE_SCHEDULED,
            cls.PUBLISHED,
        ]

    @classmethod
    def open_states(cls):
        return [s for s in cls.values if s not in TERMINAL_STATES]


#: Etats terminaux : plus aucune transition sortante sauf reouverture explicite.
TERMINAL_STATES = frozenset(
    {
        CaseStatus.CLOSED,
        CaseStatus.REJECTED,
        CaseStatus.DUPLICATE,
        CaseStatus.OUT_OF_SCOPE,
        CaseStatus.NOT_APPLICABLE,
    }
)

#: Etats consideres comme "resolus sans suite".
DISMISSED_STATES = frozenset(
    {
        CaseStatus.REJECTED,
        CaseStatus.DUPLICATE,
        CaseStatus.OUT_OF_SCOPE,
        CaseStatus.NOT_APPLICABLE,
        CaseStatus.INFORMATIVE,
    }
)

#: Issues de triage accessibles depuis presque tous les etats d'analyse.
_TRIAGE_OUTCOMES = [
    CaseStatus.DUPLICATE,
    CaseStatus.REJECTED,
    CaseStatus.OUT_OF_SCOPE,
    CaseStatus.NOT_APPLICABLE,
    CaseStatus.INFORMATIVE,
]

# ---------------------------------------------------------------------------
# Workflow CVD (programme VDP)
# ---------------------------------------------------------------------------
VDP_TRANSITIONS = {
    CaseStatus.DRAFT: [CaseStatus.SUBMITTED],
    CaseStatus.SUBMITTED: [CaseStatus.RECEIVED, CaseStatus.TRIAGE],
    CaseStatus.RECEIVED: [CaseStatus.ACKNOWLEDGED, CaseStatus.TRIAGE],
    CaseStatus.ACKNOWLEDGED: [CaseStatus.TRIAGE],
    CaseStatus.TRIAGE: [
        CaseStatus.NEEDS_INFORMATION,
        CaseStatus.VALIDATED,
        *_TRIAGE_OUTCOMES,
    ],
    CaseStatus.NEEDS_INFORMATION: [CaseStatus.TRIAGE, *_TRIAGE_OUTCOMES],
    CaseStatus.VALIDATED: [
        CaseStatus.IN_PROGRESS,
        CaseStatus.VENDOR_CONTACTED,
        CaseStatus.NEEDS_INFORMATION,
        CaseStatus.DUPLICATE,
    ],
    CaseStatus.IN_PROGRESS: [CaseStatus.VENDOR_CONTACTED, CaseStatus.REMEDIATION],
    CaseStatus.VENDOR_CONTACTED: [
        CaseStatus.VENDOR_ACKNOWLEDGED,
        CaseStatus.REMEDIATION,
        CaseStatus.DISCLOSURE_SCHEDULED,
    ],
    CaseStatus.VENDOR_ACKNOWLEDGED: [CaseStatus.REMEDIATION],
    CaseStatus.REMEDIATION: [CaseStatus.FIX_AVAILABLE, CaseStatus.DISCLOSURE_SCHEDULED],
    CaseStatus.FIX_AVAILABLE: [CaseStatus.VERIFICATION],
    CaseStatus.VERIFICATION: [
        CaseStatus.FIX_VERIFIED,
        CaseStatus.REMEDIATION,
    ],
    CaseStatus.FIX_VERIFIED: [CaseStatus.DISCLOSURE_SCHEDULED, CaseStatus.CLOSED],
    CaseStatus.DISCLOSURE_SCHEDULED: [CaseStatus.PUBLISHED, CaseStatus.CLOSED],
    CaseStatus.PUBLISHED: [CaseStatus.CLOSED],
    CaseStatus.INFORMATIVE: [CaseStatus.CLOSED],
}

# ---------------------------------------------------------------------------
# Workflow Bug Bounty
# ---------------------------------------------------------------------------
BOUNTY_TRANSITIONS = {
    CaseStatus.DRAFT: [CaseStatus.SUBMITTED],
    CaseStatus.SUBMITTED: [CaseStatus.RECEIVED, CaseStatus.TRIAGE],
    CaseStatus.RECEIVED: [CaseStatus.ACKNOWLEDGED, CaseStatus.TRIAGE],
    CaseStatus.ACKNOWLEDGED: [CaseStatus.TRIAGE],
    CaseStatus.TRIAGE: [
        CaseStatus.NEEDS_INFORMATION,
        CaseStatus.VALIDATED,
        *_TRIAGE_OUTCOMES,
    ],
    CaseStatus.NEEDS_INFORMATION: [CaseStatus.TRIAGE, *_TRIAGE_OUTCOMES],
    CaseStatus.VALIDATED: [
        CaseStatus.SEVERITY_ASSIGNED,
        CaseStatus.NEEDS_INFORMATION,
        CaseStatus.DUPLICATE,
    ],
    CaseStatus.SEVERITY_ASSIGNED: [CaseStatus.BOUNTY_REVIEW, CaseStatus.REMEDIATION],
    CaseStatus.BOUNTY_REVIEW: [CaseStatus.REWARD_APPROVED, CaseStatus.REMEDIATION],
    CaseStatus.REWARD_APPROVED: [CaseStatus.REMEDIATION],
    CaseStatus.REMEDIATION: [CaseStatus.FIX_AVAILABLE, CaseStatus.VERIFICATION],
    CaseStatus.FIX_AVAILABLE: [CaseStatus.VERIFICATION],
    CaseStatus.VERIFICATION: [CaseStatus.FIX_VERIFIED, CaseStatus.REMEDIATION],
    CaseStatus.FIX_VERIFIED: [CaseStatus.DISCLOSURE_SCHEDULED, CaseStatus.CLOSED],
    CaseStatus.DISCLOSURE_SCHEDULED: [CaseStatus.PUBLISHED, CaseStatus.CLOSED],
    CaseStatus.PUBLISHED: [CaseStatus.CLOSED],
    CaseStatus.INFORMATIVE: [CaseStatus.CLOSED],
}

#: Capacite RBAC exigee au-dela de CHANGE_CASE_STATUS pour certains etats.
TRANSITION_CAPABILITIES = {
    CaseStatus.VALIDATED: Capability.TRIAGE_CASE,
    CaseStatus.REJECTED: Capability.TRIAGE_CASE,
    CaseStatus.DUPLICATE: Capability.TRIAGE_CASE,
    CaseStatus.OUT_OF_SCOPE: Capability.TRIAGE_CASE,
    CaseStatus.NOT_APPLICABLE: Capability.TRIAGE_CASE,
    CaseStatus.INFORMATIVE: Capability.TRIAGE_CASE,
    CaseStatus.SEVERITY_ASSIGNED: Capability.SET_SEVERITY,
    CaseStatus.BOUNTY_REVIEW: Capability.PROPOSE_BOUNTY,
    CaseStatus.REWARD_APPROVED: Capability.APPROVE_BOUNTY,
    CaseStatus.PUBLISHED: Capability.PUBLISH_ADVISORY,
}

#: Colonnes du tableau Kanban (regroupement des etats).
KANBAN_COLUMNS = [
    (
        "SUBMITTED",
        "Soumis",
        [CaseStatus.SUBMITTED, CaseStatus.RECEIVED, CaseStatus.ACKNOWLEDGED],
    ),
    ("TRIAGE", "Triage", [CaseStatus.TRIAGE, CaseStatus.NEEDS_INFORMATION]),
    (
        "VALIDATED",
        "Validé",
        [
            CaseStatus.VALIDATED,
            CaseStatus.SEVERITY_ASSIGNED,
            CaseStatus.BOUNTY_REVIEW,
            CaseStatus.REWARD_APPROVED,
        ],
    ),
    (
        "REMEDIATION",
        "Remédiation",
        [
            CaseStatus.IN_PROGRESS,
            CaseStatus.VENDOR_CONTACTED,
            CaseStatus.VENDOR_ACKNOWLEDGED,
            CaseStatus.REMEDIATION,
            CaseStatus.FIX_AVAILABLE,
        ],
    ),
    ("VERIFICATION", "Vérification", [CaseStatus.VERIFICATION, CaseStatus.FIX_VERIFIED]),
    ("DISCLOSURE", "Divulgation", [CaseStatus.DISCLOSURE_SCHEDULED, CaseStatus.PUBLISHED]),
    (
        "CLOSED",
        "Clos",
        [
            CaseStatus.CLOSED,
            CaseStatus.REJECTED,
            CaseStatus.DUPLICATE,
            CaseStatus.OUT_OF_SCOPE,
            CaseStatus.NOT_APPLICABLE,
            CaseStatus.INFORMATIVE,
        ],
    ),
]


class TransitionNotAllowed(Exception):
    """Transition d'etat refusee par la machine a etats."""


def transitions_for(workflow):
    from .constants import WorkflowType

    if workflow == WorkflowType.BUG_BOUNTY:
        return BOUNTY_TRANSITIONS
    return VDP_TRANSITIONS


def allowed_targets(current_status, workflow):
    """Etats atteignables depuis `current_status` pour ce workflow."""
    return list(transitions_for(workflow).get(current_status, []))


def can_transition(current_status, target_status, workflow):
    return target_status in allowed_targets(current_status, workflow)


def required_capability(target_status):
    return TRANSITION_CAPABILITIES.get(target_status, Capability.CHANGE_CASE_STATUS)


def check_transition(current_status, target_status, workflow, user=None):
    """Valide une transition. Leve TransitionNotAllowed si elle est interdite."""
    if current_status == target_status:
        raise TransitionNotAllowed("Le case est déjà dans cet état.")
    if not can_transition(current_status, target_status, workflow):
        raise TransitionNotAllowed(
            f"Transition interdite : {current_status} -> {target_status} "
            f"(workflow {workflow})."
        )
    if user is not None:
        needed = required_capability(target_status)
        if not user.has_capability(needed):
            raise TransitionNotAllowed(f"Capacité requise pour cette transition : {needed}.")
        if not user.has_capability(Capability.CHANGE_CASE_STATUS):
            raise TransitionNotAllowed(
                "Vous n'êtes pas autorisé à changer le statut d'un case."
            )
    return True


def kanban_column_for(status):
    for key, _label, states in KANBAN_COLUMNS:
        if status in states:
            return key
    return "CLOSED"
