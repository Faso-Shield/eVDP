"""Alimente le grand livre du Wallet a partir de l'historique existant.

Chaque recompense deja approuvee (ou payee) donne une ecriture de credit ;
chaque versement enregistre donne une ecriture de versement hors
plateforme. Le solde n'est jamais stocke : il se deduit de ces ecritures.
"""

from django.db import migrations


def forwards(apps, schema_editor):
    Bounty = apps.get_model("bounty", "Bounty")
    BountyPayment = apps.get_model("bounty", "BountyPayment")
    WalletEntry = apps.get_model("bounty", "WalletEntry")

    for bounty in Bounty.objects.filter(
        status__in=["APPROVED", "PAID"], researcher__isnull=False
    ).select_related("case"):
        if WalletEntry.objects.filter(bounty=bounty, kind="CREDIT").exists():
            continue
        WalletEntry.objects.create(
            researcher_id=bounty.researcher_id,
            bounty=bounty,
            kind="CREDIT",
            amount=bounty.approved_amount or bounty.proposed_amount,
            currency=bounty.currency,
            note=f"Prime {bounty.case.case_id} (reprise)",
            created_by_id=bounty.decided_by_id,
        )
    for payment in BountyPayment.objects.filter(
        bounty__researcher__isnull=False
    ).select_related("bounty"):
        WalletEntry.objects.create(
            researcher_id=payment.bounty.researcher_id,
            bounty_id=payment.bounty_id,
            kind="PAYOUT",
            amount=-payment.amount,
            currency=payment.currency,
            note=f"Versement hors plateforme {payment.reference} (reprise)".strip(),
            created_by_id=payment.recorded_by_id,
        )


class Migration(migrations.Migration):
    dependencies = [("bounty", "0005_wallet_ledger")]

    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
