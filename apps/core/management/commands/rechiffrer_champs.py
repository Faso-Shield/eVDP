"""Reecrit tous les champs chiffres avec la premiere cle de FIELD_ENCRYPTION_KEY.

Rotation : placer la nouvelle cle en tete (`nouvelle,ancienne`), lancer cette
commande, puis retirer l'ancienne cle.
"""

from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import transaction

from apps.core.fields import encrypted_field_names, rewrite_encrypted_fields


class Command(BaseCommand):
    help = "Rechiffre les champs chiffres au repos avec la cle courante."

    def handle(self, *args, **options):
        for model in apps.get_models():
            if not encrypted_field_names(model):
                continue
            with transaction.atomic():
                count = rewrite_encrypted_fields(model)
            self.stdout.write(f"{model._meta.label} : {count} ligne(s) rechiffree(s)")
