"""Constantes du module de coordination."""

from django.db import models


class WorkflowType(models.TextChoices):
    VDP = "VDP", "Divulgation coordonnée (CVD)"
    BUG_BOUNTY = "BUG_BOUNTY", "Bug Bounty"


class Confidentiality(models.TextChoices):
    """Canal d'un message de dossier (matrice de visibilite, workflow v2).

    * RESEARCHER : canal chercheur -- declarant et equipe CSIRT, jamais la DSI ;
    * ORGANIZATION : canal interne CSIRT <-> organisation -- jamais le
      declarant ni l'agent de triage ;
    * INTERNAL : notes de triage et d'analyse -- equipe CSIRT uniquement.
    """

    RESEARCHER = "RESEARCHER", "Canal chercheur"
    ORGANIZATION = "ORGANIZATION", "Canal CSIRT ↔ organisation"
    INTERNAL = "INTERNAL", "Notes de triage et d'analyse"


class TimelineEventType(models.TextChoices):
    REPORT_RECEIVED = "REPORT_RECEIVED", "Rapport reçu"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accusé de réception"
    TRIAGE_STARTED = "TRIAGE_STARTED", "Rapport déclaré recevable"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED", "Informations demandées"
    INFORMATION_PROVIDED = "INFORMATION_PROVIDED", "Compléments reçus"
    QUALIFICATION_SUBMITTED = "QUALIFICATION_SUBMITTED", "Qualification soumise"
    VALIDATED = "VALIDATED", "Vulnérabilité validée"
    SEVERITY_SET = "SEVERITY_SET", "Sévérité attribuée"
    ORGANIZATION_CONTACTED = "ORGANIZATION_CONTACTED", "Organisation contactée"
    ORGANIZATION_ACKNOWLEDGED = "ORGANIZATION_ACKNOWLEDGED", "Plan de remédiation soumis"
    FIX_PROVIDED = "FIX_PROVIDED", "Correctif fourni"
    FIX_REJECTED = "FIX_REJECTED", "Correctif jugé insuffisant"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    DISCLOSURE_SCHEDULED = "DISCLOSURE_SCHEDULED", "Divulgation planifiée"
    ADVISORY_SUBMITTED = "ADVISORY_SUBMITTED", "Advisory soumis en relecture"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publié"
    REWARD_PROPOSED = "REWARD_PROPOSED", "Prime proposée"
    REWARD_APPROVED = "REWARD_APPROVED", "Récompense approuvée"
    REJECTION_PROPOSED = "REJECTION_PROPOSED", "Rejet proposé"
    DUPLICATE_MARKED = "DUPLICATE_MARKED", "Doublon identifié"
    REJECTED = "REJECTED", "Rapport rejeté"
    RETURNED = "RETURNED", "Renvoyé à l'auteur"
    ESCALATED = "ESCALATED", "Dossier escaladé"
    CLOSED = "CLOSED", "Case clos"
    STATUS_CHANGED = "STATUS_CHANGED", "Changement de statut"
    ASSIGNED = "ASSIGNED", "Assignation"
    NOTE = "NOTE", "Note"


class SLAKind(models.TextChoices):
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT", "Accusé de réception"
    TRIAGE = "TRIAGE", "Recevabilité et analyse"
    VALIDATION = "VALIDATION", "Validation de la qualification"
    VENDOR_RESPONSE = "VENDOR_RESPONSE", "Réponse de l'organisation"
    REMEDIATION = "REMEDIATION", "Remédiation"
    VERIFICATION = "VERIFICATION", "Vérification du correctif"
    DISCLOSURE = "DISCLOSURE", "Divulgation"


class SLAState(models.TextChoices):
    PENDING = "PENDING", "En cours"
    APPROACHING = "APPROACHING", "Échéance proche"
    MET = "MET", "Respecte"
    BREACHED = "BREACHED", "Dépassé"
    CANCELLED = "CANCELLED", "Annulé"


class ParticipantRole(models.TextChoices):
    REPORTER = "REPORTER", "Déclarant"
    ANALYST = "ANALYST", "Analyste CSIRT"
    COORDINATOR = "COORDINATOR", "Coordinateur"
    ORGANIZATION = "ORGANIZATION", "Organisation affectée"
    DSI = "DSI", "DSI"
    OBSERVER = "OBSERVER", "Observateur"
