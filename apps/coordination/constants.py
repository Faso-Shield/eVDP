"""Constantes du module de coordination."""

from django.db import models


class WorkflowType(models.TextChoices):
    VDP = "VDP", "Divulgation coordonnée (CVD)"
    BUG_BOUNTY = "BUG_BOUNTY", "Bug Bounty"


class Confidentiality(models.TextChoices):
    """Niveau de confidentialité d'un message de case (inspiré du TLP)."""

    PARTICIPANTS = "PARTICIPANTS", "Participants du case"
    INTERNAL = "INTERNAL", "Interne CSIRT"
    RESTRICTED = "RESTRICTED", "Restreint (coordination nationale)"


class TimelineEventType(models.TextChoices):
    REPORT_RECEIVED = "REPORT_RECEIVED", "Rapport reçu"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accusé de réception"
    TRIAGE_STARTED = "TRIAGE_STARTED", "Triage engagé"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED", "Informations demandées"
    VALIDATED = "VALIDATED", "Vulnérabilité validée"
    SEVERITY_SET = "SEVERITY_SET", "Sévérité attribuée"
    ORGANIZATION_CONTACTED = "ORGANIZATION_CONTACTED", "Organisation contactée"
    ORGANIZATION_ACKNOWLEDGED = "ORGANIZATION_ACKNOWLEDGED", "Organisation a répondu"
    FIX_PROVIDED = "FIX_PROVIDED", "Correctif fourni"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    DISCLOSURE_SCHEDULED = "DISCLOSURE_SCHEDULED", "Divulgation planifiée"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publié"
    REWARD_APPROVED = "REWARD_APPROVED", "Récompense approuvée"
    DUPLICATE_MARKED = "DUPLICATE_MARKED", "Doublon identifié"
    REJECTED = "REJECTED", "Rapport rejeté"
    CLOSED = "CLOSED", "Case clos"
    STATUS_CHANGED = "STATUS_CHANGED", "Changement de statut"
    ASSIGNED = "ASSIGNED", "Assignation"
    NOTE = "NOTE", "Note"


class SLAKind(models.TextChoices):
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT", "Accusé de réception"
    TRIAGE = "TRIAGE", "Premier triage"
    VENDOR_RESPONSE = "VENDOR_RESPONSE", "Réponse de l'organisation"
    REMEDIATION = "REMEDIATION", "Remédiation"
    DISCLOSURE = "DISCLOSURE", "Divulgation"


class SLAState(models.TextChoices):
    PENDING = "PENDING", "En cours"
    APPROACHING = "APPROACHING", "Échéance proche"
    MET = "MET", "Respecté"
    BREACHED = "BREACHED", "Dépassé"
    CANCELLED = "CANCELLED", "Annulé"


class ParticipantRole(models.TextChoices):
    REPORTER = "REPORTER", "Déclarant"
    ANALYST = "ANALYST", "Analyste CSIRT"
    COORDINATOR = "COORDINATOR", "Coordinateur"
    ORGANIZATION = "ORGANIZATION", "Organisation affectée"
    DSI = "DSI", "DSI"
    OBSERVER = "OBSERVER", "Observateur"
