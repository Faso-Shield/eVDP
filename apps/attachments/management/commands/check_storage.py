"""Diagnostic du stockage des pieces jointes (MinIO / S3 ou disque).

    docker compose exec evdp-web python manage.py check_storage

Ecrit, relit puis supprime un petit fichier de test avec exactement la
configuration utilisee par l'application, et affiche en clair l'etape qui
echoue et l'erreur renvoyee par le stockage.
"""

import secrets

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Verifie que le stockage des pieces jointes accepte ecriture, lecture et suppression."
    )

    def handle(self, *args, **options):
        backend = default_storage.__class__.__name__
        self.stdout.write(f"Stockage : {backend}")
        if getattr(settings, "USE_S3", False):
            opts = settings.STORAGES["default"].get("OPTIONS", {})
            self.stdout.write(f"  endpoint : {opts.get('endpoint_url')}")
            self.stdout.write(f"  bucket   : {opts.get('bucket_name')}")
            self.stdout.write(f"  cle      : {opts.get('access_key') or '(vide)'}")

        name = f"_diagnostic/check-{secrets.token_hex(6)}.txt"
        payload = b"eVDP check_storage"

        saved = self._step("ecriture", default_storage.save, name, ContentFile(payload))
        content = self._step("lecture", self._read, saved)
        if content != payload:
            raise CommandError("Le contenu relu differe du contenu ecrit.")
        self._step("suppression", default_storage.delete, saved)
        self.stdout.write(self.style.SUCCESS("Stockage des pieces jointes operationnel."))

    @staticmethod
    def _read(name):
        with default_storage.open(name, "rb") as handle:
            return handle.read()

    def _step(self, label, func, *args):
        try:
            result = func(*args)
        except Exception as exc:
            raise CommandError(
                f"Echec a l'etape « {label} » : {exc.__class__.__name__}: {exc}"
            ) from exc
        self.stdout.write(self.style.SUCCESS(f"  {label} : OK"))
        return result
