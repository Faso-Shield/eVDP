"""Passage du stockage MinIO au disque."""

from io import StringIO

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, InMemoryStorage
from django.core.management import CommandError, call_command

from apps.attachments.services import store_attachment
from apps.core.management.commands import copier_fichiers_s3_vers_disque as commande

from .test_attachments import upload

pytestmark = pytest.mark.django_db


@pytest.fixture
def moved_to_s3(monkeypatch, case_alpha, researcher_a):
    """Une piece jointe dont le fichier n'existe que sur la source S3."""
    attachment = store_attachment(
        upload("preuve.txt", b"contenu migre"), researcher_a, case=case_alpha
    )
    disk = FileSystemStorage()
    source = InMemoryStorage()
    with disk.open(attachment.file.name, "rb") as handle:
        source.save(attachment.file.name, ContentFile(handle.read()))
    disk.delete(attachment.file.name)
    monkeypatch.setattr(commande, "source_storage", lambda: source)
    return attachment


def test_files_are_copied_to_disk_under_the_same_name(moved_to_s3):
    disk = FileSystemStorage()
    call_command("copier_fichiers_s3_vers_disque", "--dry-run", stdout=StringIO())
    assert not disk.exists(moved_to_s3.file.name)

    out = StringIO()
    call_command("copier_fichiers_s3_vers_disque", stdout=out)
    assert disk.exists(moved_to_s3.file.name)
    with disk.open(moved_to_s3.file.name, "rb") as handle:
        assert handle.read() == b"contenu migre"
    assert "1 fichier(s) copies" in out.getvalue()

    # Rejouable : rien n'est recopie.
    out = StringIO()
    call_command("copier_fichiers_s3_vers_disque", stdout=out)
    assert "0 fichier(s) copies" in out.getvalue()


def test_a_file_missing_from_the_source_is_reported(monkeypatch, moved_to_s3):
    monkeypatch.setattr(commande, "source_storage", InMemoryStorage)
    with pytest.raises(CommandError, match="anomalie"):
        call_command("copier_fichiers_s3_vers_disque", stdout=StringIO(), stderr=StringIO())


def test_media_is_never_served_directly_even_in_debug():
    """En DEBUG, Django servait /media/ : une piece jointe y etait lisible
    sans passer par la vue qui verifie les droits."""
    from pathlib import Path

    urls = (Path(__file__).resolve().parent.parent / "config" / "urls.py").read_text(
        encoding="utf-8"
    )
    assert "MEDIA_URL" not in urls
