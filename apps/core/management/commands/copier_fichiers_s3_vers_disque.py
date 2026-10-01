"""Copie les fichiers stockes sur S3/MinIO vers le stockage disque (MEDIA_ROOT).

Pour une instance qui passe de MinIO au disque (USE_S3=False). La source est
lue avec les variables MINIO_* de l'environnement, quelle que soit la valeur
de USE_S3. Chaque fichier garde son nom de stockage : aucune ligne de la base
n'est modifiee. Un fichier deja present sur le disque n'est pas recopie.

Les pieces jointes sont controlees par leur empreinte SHA-256 apres copie.

    python manage.py copier_fichiers_s3_vers_disque [--dry-run]
"""

import hashlib

from django.apps import apps
from django.core.files.storage import FileSystemStorage
from django.core.management.base import BaseCommand, CommandError
from django.db import models


def source_storage():
    """Stockage S3 construit depuis l'environnement (MINIO_*)."""
    import environ
    from storages.backends.s3 import S3Storage

    env = environ.Env()
    return S3Storage(
        bucket_name=env("MINIO_BUCKET", default="evdp-attachments"),
        access_key=env("MINIO_ACCESS_KEY", default=""),
        secret_key=env("MINIO_SECRET_KEY", default=""),
        endpoint_url=env("MINIO_ENDPOINT", default="http://evdp-minio:9000"),
        region_name=env("MINIO_REGION", default="us-east-1"),
        signature_version="s3v4",
        addressing_style="path",
    )


def _file_fields():
    for model in apps.get_models():
        for field in model._meta.concrete_fields:
            if isinstance(field, models.FileField):
                yield model, field


class Command(BaseCommand):
    help = "Copie les fichiers de S3/MinIO vers MEDIA_ROOT (passage au stockage disque)."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Compte sans rien copier.")

    def handle(self, *args, dry_run=False, **options):
        source = source_storage()
        target = FileSystemStorage()
        copied = present = missing = 0
        errors = []
        for model, field in _file_fields():
            names = (
                model.objects.exclude(**{field.name: ""})
                .values_list(field.name, flat=True)
                .iterator()
            )
            for name in names:
                if not name:
                    continue
                if target.exists(name):
                    present += 1
                    continue
                if not source.exists(name):
                    missing += 1
                    errors.append(f"absent de la source : {name}")
                    continue
                if not dry_run:
                    with source.open(name, "rb") as handle:
                        saved = target.save(name, handle)
                    if saved != name:
                        raise CommandError(f"Nom modifie a l'ecriture : {name} -> {saved}")
                copied += 1
        if not dry_run:
            errors += self._verify_attachments(target)

        verb = "a copier" if dry_run else "copies"
        self.stdout.write(
            f"{copied} fichier(s) {verb}, {present} deja sur disque, {missing} absent(s)."
        )
        for error in errors:
            self.stderr.write(error)
        if errors:
            raise CommandError(f"{len(errors)} anomalie(s) : voir ci-dessus.")

    def _verify_attachments(self, target):
        """L'empreinte enregistree au depot doit correspondre au fichier copie."""
        from apps.attachments.models import Attachment

        errors = []
        for attachment in Attachment.objects.exclude(file="").iterator():
            if not target.exists(attachment.file.name):
                continue
            digest = hashlib.sha256()
            with target.open(attachment.file.name, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            if digest.hexdigest() != attachment.sha256:
                errors.append(f"empreinte differente : {attachment.file.name}")
        return errors
