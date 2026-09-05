"""Politique SLA nationale par defaut.

Sans politique par defaut, aucune echeance n'est calculee et la plateforme
perd son pilotage des delais. Cette migration garantit qu'une installation
neuve dispose immediatement des SLA prevus par la politique nationale.
Les valeurs restent modifiables depuis l'administration.
"""

from django.db import migrations

DEFAULTS = {
    "name": "SLA national par defaut",
    "is_default": True,
    "acknowledgement_hours": 72,
    "triage_days": 5,
    "vendor_response_days": 7,
    "remediation_days_critical": 30,
    "remediation_days_high": 30,
    "remediation_days_medium": 60,
    "remediation_days_low": 90,
    "disclosure_delay_days": 90,
    "warning_ratio": 80,
}


def create_default_policy(apps, schema_editor):
    SLAPolicy = apps.get_model("coordination", "SLAPolicy")
    if SLAPolicy.objects.exists():
        return
    SLAPolicy.objects.create(**DEFAULTS)


def remove_default_policy(apps, schema_editor):
    SLAPolicy = apps.get_model("coordination", "SLAPolicy")
    SLAPolicy.objects.filter(name=DEFAULTS["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [("coordination", "0002_initial")]

    operations = [
        migrations.RunPython(create_default_policy, remove_default_policy),
    ]
