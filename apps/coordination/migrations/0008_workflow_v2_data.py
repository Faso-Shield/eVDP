"""Migration de donnees : 24 statuts historiques -> workflow v2.

Mapping (SPEC-eVDP-2026-V2, section « Ecarts avec le code actuel ») :

    DRAFT, SUBMITTED, RECEIVED              -> SUBMITTED  (RECEIVED disparait)
    ACKNOWLEDGED                            -> ACKNOWLEDGED
    TRIAGE                                  -> IN_ANALYSIS
    NEEDS_INFORMATION                       -> NEEDS_INFORMATION (origine : IN_ANALYSIS)
    VALIDATED, SEVERITY_ASSIGNED,
    BOUNTY_REVIEW, REWARD_APPROVED,
    IN_PROGRESS                             -> VALIDATED
    VENDOR_CONTACTED, VENDOR_ACKNOWLEDGED   -> VENDOR_NOTIFIED
    REMEDIATION                             -> REMEDIATION_IN_PROGRESS
    FIX_AVAILABLE, VERIFICATION             -> FIX_AVAILABLE
    FIX_VERIFIED, DISCLOSURE_SCHEDULED      -> FIX_VERIFIED
    PUBLISHED, CLOSED                       -> CLOSED
    REJECTED, OUT_OF_SCOPE,
    NOT_APPLICABLE, INFORMATIVE             -> REJECTED
    DUPLICATE                               -> DUPLICATE

L'historique des statuts est converti avec la meme table, pour que les
choix restent valides et que la regle des quatre yeux lise un historique
coherent. Les dossiers deja passes par l'etape 2 recoivent une checklist de
recevabilite complete. La branche prime est initialisee a partir de la
recompense existante. Les politiques SLA encore aux anciennes valeurs par
defaut sont alignees sur la spec v2 (Elevee 60 j, Moyenne 90 j, plan de
l'organisation 5 j, alerte a 75 %).

La migration inverse est volontairement approximative (le workflow v1 etait
plus fin sur certaines etapes) : elle ramene chaque statut v2 vers son
equivalent v1 le plus proche.
"""

from django.db import migrations

STATUS_MAP = {
    "DRAFT": "SUBMITTED",
    "SUBMITTED": "SUBMITTED",
    "RECEIVED": "SUBMITTED",
    "ACKNOWLEDGED": "ACKNOWLEDGED",
    "TRIAGE": "IN_ANALYSIS",
    "NEEDS_INFORMATION": "NEEDS_INFORMATION",
    "VALIDATED": "VALIDATED",
    "SEVERITY_ASSIGNED": "VALIDATED",
    "BOUNTY_REVIEW": "VALIDATED",
    "REWARD_APPROVED": "VALIDATED",
    "IN_PROGRESS": "VALIDATED",
    "VENDOR_CONTACTED": "VENDOR_NOTIFIED",
    "VENDOR_ACKNOWLEDGED": "VENDOR_NOTIFIED",
    "REMEDIATION": "REMEDIATION_IN_PROGRESS",
    "FIX_AVAILABLE": "FIX_AVAILABLE",
    "VERIFICATION": "FIX_AVAILABLE",
    "FIX_VERIFIED": "FIX_VERIFIED",
    "DISCLOSURE_SCHEDULED": "FIX_VERIFIED",
    "PUBLISHED": "CLOSED",
    "CLOSED": "CLOSED",
    "REJECTED": "REJECTED",
    "OUT_OF_SCOPE": "REJECTED",
    "NOT_APPLICABLE": "REJECTED",
    "INFORMATIVE": "REJECTED",
    "DUPLICATE": "DUPLICATE",
}

REVERSE_MAP = {
    "SUBMITTED": "SUBMITTED",
    "ACKNOWLEDGED": "ACKNOWLEDGED",
    "IN_ANALYSIS": "TRIAGE",
    "VALIDATION_PENDING": "TRIAGE",
    "VALIDATED": "VALIDATED",
    "VENDOR_NOTIFIED": "VENDOR_CONTACTED",
    "REMEDIATION_IN_PROGRESS": "REMEDIATION",
    "FIX_AVAILABLE": "FIX_AVAILABLE",
    "FIX_VERIFIED": "FIX_VERIFIED",
    "ADVISORY_REVIEW": "DISCLOSURE_SCHEDULED",
    "CLOSED": "CLOSED",
    "NEEDS_INFORMATION": "NEEDS_INFORMATION",
    "REJECTION_PENDING": "TRIAGE",
    "REJECTED": "REJECTED",
    "DUPLICATE": "DUPLICATE",
}

#: Statuts v2 attestant que la recevabilite (etape 2) est acquise.
PAST_ADMISSIBILITY = {
    "NEEDS_INFORMATION",  # origine IN_ANALYSIS apres migration
    "IN_ANALYSIS",
    "VALIDATION_PENDING",
    "VALIDATED",
    "VENDOR_NOTIFIED",
    "REMEDIATION_IN_PROGRESS",
    "FIX_AVAILABLE",
    "FIX_VERIFIED",
    "ADVISORY_REVIEW",
    "CLOSED",
}

#: Statut de recompense v1 -> statut de la branche prime v2.
BOUNTY_MAP = {
    "PENDING": "BOUNTY_PROPOSED",
    "UNDER_REVIEW": "BOUNTY_PROPOSED",
    "APPROVED": "BOUNTY_CREDITED",
    "PAID": "BOUNTY_CREDITED",
    "REJECTED": "NOT_ELIGIBLE",
    "CANCELLED": "NOT_ELIGIBLE",
}

#: Anciennes valeurs par defaut -> nouvelles (seulement si inchangees).
SLA_DEFAULTS = {
    "remediation_days_high": (30, 60),
    "remediation_days_medium": (60, 90),
    "vendor_response_days": (7, 5),
    "warning_ratio": (80, 75),
}


def _map_history(apps, mapping):
    History = apps.get_model("coordination", "CaseStatusHistory")
    for old, new in mapping.items():
        if old == new:
            continue
        History.objects.filter(from_status=old).update(from_status=new)
        History.objects.filter(to_status=old).update(to_status=new)


def forwards(apps, schema_editor):
    Case = apps.get_model("coordination", "Case")
    Bounty = apps.get_model("bounty", "Bounty")
    SLAPolicy = apps.get_model("coordination", "SLAPolicy")

    for old, new in STATUS_MAP.items():
        if old != new:
            Case.objects.filter(status=old).update(status=new)
    Case.objects.filter(status="NEEDS_INFORMATION").update(
        status_before_exception="IN_ANALYSIS"
    )
    _map_history(apps, STATUS_MAP)

    Case.objects.filter(status__in=PAST_ADMISSIBILITY).update(
        admissibility_scope_ok=True,
        admissibility_organization_ok=True,
        admissibility_attachment_ok=True,
    )

    # Branche prime.
    validated = Case.objects.exclude(validated_at=None)
    bounty_by_case = dict(Bounty.objects.values_list("case_id", "status"))
    for case in validated.select_related("program"):
        if case.id in bounty_by_case:
            case.bounty_status = BOUNTY_MAP.get(bounty_by_case[case.id], "NOT_ELIGIBLE")
        elif (
            case.program_id
            and case.program.program_type == "BUG_BOUNTY"
            and case.reporter_id
            and case.status not in ("REJECTED", "DUPLICATE")
        ):
            case.bounty_status = "BOUNTY_ELIGIBLE"
        else:
            case.bounty_status = "NOT_ELIGIBLE"
        case.save(update_fields=["bounty_status"])
    # Dossiers clos sans validation : pas de prime a attendre.
    Case.objects.filter(validated_at=None, status__in=["CLOSED", "REJECTED", "DUPLICATE"]).update(
        bounty_status="NOT_ELIGIBLE"
    )

    for field, (old, new) in SLA_DEFAULTS.items():
        SLAPolicy.objects.filter(**{field: old}).update(**{field: new})


def backwards(apps, schema_editor):
    Case = apps.get_model("coordination", "Case")
    for new, old in REVERSE_MAP.items():
        if new != old:
            Case.objects.filter(status=new).update(status=old)
    _map_history(apps, REVERSE_MAP)


class Migration(migrations.Migration):
    dependencies = [
        ("coordination", "0007_workflow_v2"),
        ("bounty", "0005_wallet_ledger"),
    ]

    operations = [migrations.RunPython(forwards, backwards)]
