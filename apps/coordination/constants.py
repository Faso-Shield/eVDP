"""Constantes du module de coordination."""

from django.db import models


class WorkflowType(models.TextChoices):
    VDP = "VDP", "Divulgation coordonnee (CVD)"
    BUG_BOUNTY = "BUG_BOUNTY", "Bug Bounty"


class Confidentiality(models.TextChoices):
    """Niveau de confidentialite d'un message de case (inspire du TLP)."""

    PARTICIPANTS = "PARTICIPANTS", "Participants du case"
    INTERNAL = "INTERNAL", "Interne CSIRT"
    RESTRICTED = "RESTRICTED", "Restreint (coordination nationale)"


class TimelineEventType(models.TextChoices):
    REPORT_RECEIVED = "REPORT_RECEIVED", "Rapport recu"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Accuse de reception"
    TRIAGE_STARTED = "TRIAGE_STARTED", "Triage engage"
    INFORMATION_REQUESTED = "INFORMATION_REQUESTED", "Informations demandees"
    VALIDATED = "VALIDATED", "Vulnerabilite validee"
    SEVERITY_SET = "SEVERITY_SET", "Severite attribuee"
    ORGANIZATION_CONTACTED = "ORGANIZATION_CONTACTED", "Organisation contactee"
    ORGANIZATION_ACKNOWLEDGED = "ORGANIZATION_ACKNOWLEDGED", "Organisation a repondu"
    FIX_PROVIDED = "FIX_PROVIDED", "Correctif fourni"
    FIX_VERIFIED = "FIX_VERIFIED", "Correctif verifie"
    DISCLOSURE_SCHEDULED = "DISCLOSURE_SCHEDULED", "Divulgation planifiee"
    ADVISORY_PUBLISHED = "ADVISORY_PUBLISHED", "Advisory publie"
    REWARD_APPROVED = "REWARD_APPROVED", "Recompense approuvee"
    DUPLICATE_MARKED = "DUPLICATE_MARKED", "Doublon identifie"
    REJECTED = "REJECTED", "Rapport rejete"
    CLOSED = "CLOSED", "Case clos"
    STATUS_CHANGED = "STATUS_CHANGED", "Changement de statut"
    ASSIGNED = "ASSIGNED", "Assignation"
    NOTE = "NOTE", "Note"


class SLAKind(models.TextChoices):
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT", "Accuse de reception"
    TRIAGE = "TRIAGE", "Premier triage"
    VENDOR_RESPONSE = "VENDOR_RESPONSE", "Reponse de l'organisation"
    REMEDIATION = "REMEDIATION", "Remediation"
    DISCLOSURE = "DISCLOSURE", "Divulgation"


class SLAState(models.TextChoices):
    PENDING = "PENDING", "En cours"
    APPROACHING = "APPROACHING", "Echeance proche"
    MET = "MET", "Respecte"
    BREACHED = "BREACHED", "Depasse"
    CANCELLED = "CANCELLED", "Annule"


class ParticipantRole(models.TextChoices):
    REPORTER = "REPORTER", "Declarant"
    ANALYST = "ANALYST", "Analyste CSIRT"
    COORDINATOR = "COORDINATOR", "Coordinateur"
    ORGANIZATION = "ORGANIZATION", "Organisation affectee"
    DSI = "DSI", "DSI"
    OBSERVER = "OBSERVER", "Observateur"
