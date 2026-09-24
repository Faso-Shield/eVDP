"""Constantes du module de coordination."""

from django.db import models


class WorkflowType(models.TextChoices):
    VDP = "VDP", "Divulgation coordonnée (CVD)"
    BUG_BOUNTY = "BUG_BOUNTY", "Bug Bounty"


class Confidentiality(models.TextChoices):
    """Canal d'un message de case (inspire du TLP).

    Deux canaux externes etanches (spec v2) : le declarant et l'organisation
    ne se lisent jamais directement, le CSIRT fait l'intermediaire.
    """

    PARTICIPANTS = "PARTICIPANTS", "Canal chercheur"
    ORGANIZATION = "ORGANIZATION", "Canal CSIRT ↔ organisation"
    INTERNAL = "INTERNAL", "Interne CSIRT (notes de triage et d'analyse)"
    RESTRICTED = "RESTRICTED", "Restreint (coordination nationale)"


class TimelineEventType(models.TextChoices):
    REPORT_RECEIVED = "REPORT_RECEIVED", "Rapport reçu"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accusé de réception"
    TRIAGE_STARTED = "TRIAGE_STARTED", "Déclaré recevable"
    QUALIFICATION_SUBMITTED = "QUALIFICATION_SUBMITTED", "Qualification soumise"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED", "Informations demandées"
    VALIDATED = "VALIDATED", "Vulnérabilité validée"
    SEVERITY_SET = "SEVERITY_SET", "Sévérité attribuée"
    ORGANIZATION_CONTACTED = "ORGANIZATION_CONTACTED", "Organisation contactée"
    ORGANIZATION_ACKNOWLEDGED = "ORGANIZATION_ACKNOWLEDGED", "Organisation a répondu"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED", "Plan de remédiation accepté"
    FIX_PROVIDED = "FIX_PROVIDED", "Correctif fourni"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif vérifié"
    DISCLOSURE_SCHEDULED = "DISCLOSURE_SCHEDULED", "Divulgation planifiée"
    ADVISORY_SUBMITTED = "ADVISORY_SUBMITTED", "Advisory soumis en relecture"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publié"
    REWARD_APPROVED = "REWARD_APPROVED", "Récompense approuvée"
    DUPLICATE_MARKED = "DUPLICATE_MARKED", "Doublon identifié"
    REJECTION_PROPOSED = "REJECTION_PROPOSED", "Rejet proposé"
    REJECTED = "REJECTED", "Rapport rejeté"
    SENT_BACK = "SENT_BACK", "Renvoyé à l'auteur"
    ESCALATED = "ESCALATED", "Escalade"
    CLOSED = "CLOSED", "Case clos"
    STATUS_CHANGED = "STATUS_CHANGED", "Changement de statut"
    ASSIGNED = "ASSIGNED", "Assignation"
    NOTE = "NOTE", "Note"


class SLAKind(models.TextChoices):
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT", "Accusé de réception"
    TRIAGE = "TRIAGE", "Recevabilité et qualification"
    VALIDATION = "VALIDATION", "Validation de la qualification"
    VENDOR_RESPONSE = "VENDOR_RESPONSE", "Plan de remédiation de l'organisation"
    REMEDIATION = "REMEDIATION", "Remédiation"
    VERIFICATION = "VERIFICATION", "Contre-vérification du correctif"
    DISCLOSURE = "DISCLOSURE", "Divulgation"


class SLAState(models.TextChoices):
    PENDING = "PENDING", "En cours"
    APPROACHING = "APPROACHING", "Échéance proche"
    SUSPENDED = "SUSPENDED", "Suspendu (compléments demandés)"
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
