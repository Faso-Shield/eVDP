"""Migration des donnees vers le workflow v2.

Les 24 statuts historiques sont ramenes aux 11 etapes principales et aux
sorties d'exception du document « Workflow v2 & Matrice RBAC ». Le mapping
retenu (a valider par la coordination, voir docs/cvd-workflow.md) :

    DRAFT, SUBMITTED, RECEIVED           -> SUBMITTED
    ACKNOWLEDGED, TRIAGE                 -> ACKNOWLEDGED (recevabilite a reconfirmer)
    NEEDS_INFORMATION                    -> NEEDS_INFORMATION (origine : ACKNOWLEDGED)
    VALIDATED, SEVERITY_ASSIGNED,
    BOUNTY_REVIEW, REWARD_APPROVED,
    IN_PROGRESS                          -> VALIDATED
    VENDOR_CONTACTED                     -> VENDOR_NOTIFIED
    VENDOR_ACKNOWLEDGED, REMEDIATION     -> REMEDIATION_IN_PROGRESS
    FIX_AVAILABLE, VERIFICATION          -> FIX_AVAILABLE
    FIX_VERIFIED, DISCLOSURE_SCHEDULED   -> FIX_VERIFIED
    PUBLISHED, CLOSED                    -> CLOSED
    REJECTED, OUT_OF_SCOPE,
    NOT_APPLICABLE, INFORMATIVE          -> REJECTED
    DUPLICATE                            -> DUPLICATE

L'historique des statuts (CaseStatusHistory) n'est pas reecrit : c'est une
trace d'audit, elle conserve les libelles de l'epoque.

Sont aussi migres : les canaux de messagerie, le statut de prime (champ
distinct) avec les ecritures de Wallet correspondant aux primes deja
approuvees ou versees, et la politique SLA par defaut (delais v2).
"""

from django.db import migrations

STATUS_MAP = {
    "DRAFT": "SUBMITTED",
    "RECEIVED": "SUBMITTED",
    "TRIAGE": "ACKNOWLEDGED",
    "SEVERITY_ASSIGNED": "VALIDATED",
    "BOUNTY_REVIEW": "VALIDATED",
    "REWARD_APPROVED": "VALIDATED",
    "IN_PROGRESS": "VALIDATED",
    "VENDOR_CONTACTED": "VENDOR_NOTIFIED",
    "VENDOR_ACKNOWLEDGED": "REMEDIATION_IN_PROGRESS",
    "REMEDIATION": "REMEDIATION_IN_PROGRESS",
    "VERIFICATION": "FIX_AVAILABLE",
    "DISCLOSURE_SCHEDULED": "FIX_VERIFIED",
    "PUBLISHED": "CLOSED",
    "OUT_OF_SCOPE": "REJECTED",
    "NOT_APPLICABLE": "REJECTED",
    "INFORMATIVE": "REJECTED",
}

VALIDATED_OR_LATER = {
    "VALIDATED",
    "VENDOR_NOTIFIED",
    "REMEDIATION_IN_PROGRESS",
    "FIX_AVAILABLE",
    "FIX_VERIFIED",
    "ADVISORY_REVIEW",
    "CLOSED",
}

BOUNTY_STAGE_BY_STATUS = {
    "PENDING": "BOUNTY_PROPOSED",
    "UNDER_REVIEW": "BOUNTY_PROPOSED",
    "APPROVED": "BOUNTY_CREDITED",
    "PAID": "BOUNTY_CREDITED",
    "REJECTED": "NOT_ELIGIBLE",
    "CANCELLED": "NOT_ELIGIBLE",
}

ORGANIZATION_ROLES = {"DSI_ADMIN", "ORGANIZATION_MANAGER"}

SLA_V2 = {
    "triage_days": 5,
    "validation_days": 2,
    "vendor_response_days": 5,
    "remediation_days_critical": 30,
    "remediation_days_high": 60,
    "remediation_days_medium": 90,
    "remediation_days_low": 90,
    "verification_days": 5,
    "warning_ratio": 75,
}


def forwards(apps, schema_editor):
    Case = apps.get_model("coordination", "Case")
    CaseMessage = apps.get_model("coordination", "CaseMessage")
    SLAPolicy = apps.get_model("coordination", "SLAPolicy")
    Bounty = apps.get_model("bounty", "Bounty")
    WalletEntry = apps.get_model("bounty", "WalletEntry")

    for old, new in STATUS_MAP.items():
        Case.objects.filter(status=old).update(status=new)
    Case.objects.filter(status="NEEDS_INFORMATION", return_status="").update(
        return_status="ACKNOWLEDGED"
    )
    for case in Case.objects.filter(status__in=VALIDATED_OR_LATER, vendor_notified_at=None):
        if case.status != "VALIDATED":
            case.vendor_notified_at = case.validated_at or case.updated_at
            case.save(update_fields=["vendor_notified_at"])

    # Canaux : l'ancien fil "participants" melangeait chercheur et
    # organisation ; chaque message rejoint le canal de son auteur.
    CaseMessage.objects.filter(confidentiality="RESTRICTED").update(confidentiality="INTERNAL")
    CaseMessage.objects.filter(
        confidentiality="PARTICIPANTS", author__role__in=ORGANIZATION_ROLES
    ).update(confidentiality="ORGANIZATION")
    CaseMessage.objects.filter(confidentiality="PARTICIPANTS").update(confidentiality="RESEARCHER")

    # Statut de prime et grand livre du Wallet.
    for bounty in Bounty.objects.select_related("case"):
        stage = BOUNTY_STAGE_BY_STATUS.get(bounty.status, "BOUNTY_PROPOSED")
        Case.objects.filter(pk=bounty.case_id).update(bounty_stage=stage)
        if bounty.status in ("APPROVED", "PAID") and bounty.researcher_id:
            amount = bounty.approved_amount or bounty.proposed_amount
            WalletEntry.objects.create(
                researcher_id=bounty.researcher_id,
                bounty=bounty,
                kind="CREDIT",
                amount=amount,
                currency=bounty.currency,
                label=f"Prime {bounty.case.case_id} (reprise)",
                created_by_id=bounty.decided_by_id,
            )
            for payment in bounty.payments.all():
                WalletEntry.objects.create(
                    researcher_id=bounty.researcher_id,
                    bounty=bounty,
                    kind="PAYOUT",
                    amount=-payment.amount,
                    currency=payment.currency,
                    label=f"Versement hors plateforme {payment.reference} (reprise)".strip(),
                    created_by_id=payment.recorded_by_id,
                )
    for case in Case.objects.filter(status__in=VALIDATED_OR_LATER, bounty_stage=""):
        eligible = (
            case.program_id is not None
            and case.program.program_type == "BUG_BOUNTY"
            and case.reporter_id is not None
        )
        case.bounty_stage = "BOUNTY_ELIGIBLE" if eligible else "NOT_ELIGIBLE"
        case.save(update_fields=["bounty_stage"])

    SLAPolicy.objects.filter(is_default=True).update(**SLA_V2)


class Migration(migrations.Migration):
    dependencies = [
        ("coordination", "0007_workflow_v2"),
        ("bounty", "0005_walletentry"),
        ("programs", "0001_initial"),
        ("accounts", "0008_user_is_senior_analyst"),
    ]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
