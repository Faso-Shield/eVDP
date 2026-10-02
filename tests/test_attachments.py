"""Tests des pieces jointes : validation, isolation, tracabilite."""

import io
import zipfile

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from apps.attachments.services import store_attachment, validate_upload
from apps.audit.models import AuditAction, AuditLog

pytestmark = pytest.mark.django_db


def upload(name, content=b"contenu de test", content_type="text/plain"):
    return SimpleUploadedFile(name, content, content_type=content_type)


# ------------------------------------------------------------------ validation
def test_allowed_extension_is_accepted():
    metadata = validate_upload(upload("preuve.txt"))
    assert metadata["extension"] == "txt"


def test_blocked_extension_is_rejected():
    with pytest.raises(ValidationError, match="interdite"):
        validate_upload(upload("exploit.exe", b"MZcontenu"))


def test_unlisted_extension_is_rejected():
    with pytest.raises(ValidationError, match="non autorisée"):
        validate_upload(upload("archive.tar.zst", b"data"))


def test_html_upload_is_rejected():
    """Un HTML servi depuis le domaine permettrait un XSS stocke."""
    with pytest.raises(ValidationError):
        validate_upload(upload("poc.html", b"<script>alert(1)</script>"))


def test_svg_upload_is_rejected():
    with pytest.raises(ValidationError):
        validate_upload(upload("logo.svg", b"<svg onload=alert(1)>"))


def test_executable_content_is_rejected_despite_safe_extension():
    """Un binaire renomme en .txt est detecte par sa signature."""
    with pytest.raises(ValidationError, match="exécutable"):
        validate_upload(upload("innocent.txt", b"MZ\x90\x00\x03binaire"))


def test_jpeg_signature_mismatch_is_rejected():
    with pytest.raises(ValidationError, match="signature"):
        validate_upload(upload("photo.jpg", b"%PDF-faux-jpeg"))


def test_pdf_signature_mismatch_is_rejected():
    with pytest.raises(ValidationError, match="signature"):
        validate_upload(upload("rapport.pdf", b"\x89PNG\r\n\x1a\nfaux-pdf"))


def test_valid_pdf_signature_is_accepted():
    metadata = validate_upload(upload("rapport.pdf", b"%PDF-1.7\ncontenu"))
    assert metadata["extension"] == "pdf"


def test_valid_png_signature_is_accepted():
    metadata = validate_upload(upload("image.png", b"\x89PNG\r\n\x1a\ncontenu"))
    assert metadata["extension"] == "png"


def test_elf_content_is_rejected():
    with pytest.raises(ValidationError, match="exécutable"):
        validate_upload(upload("innocent.log", b"\x7fELF\x02\x01binaire"))


def test_shell_script_content_is_rejected():
    with pytest.raises(ValidationError, match="exécutable"):
        validate_upload(upload("notes.txt", b"#!/bin/sh\nrm -rf /"))


def test_oversized_file_is_rejected(settings):
    settings.EVDP = {**settings.EVDP, "MAX_ATTACHMENT_SIZE": 10}
    with pytest.raises(ValidationError, match="volumineux"):
        validate_upload(upload("gros.txt", b"x" * 100))


def test_empty_file_is_rejected():
    with pytest.raises(ValidationError, match="vide"):
        validate_upload(upload("vide.txt", b""))


def test_file_without_extension_is_rejected():
    with pytest.raises(ValidationError, match="Extension"):
        validate_upload(upload("sansextension", b"data"))


# --------------------------------------------------------------- enregistrement
def test_storage_name_is_random_and_hides_user_filename(case_alpha, researcher_a):
    attachment = store_attachment(
        upload("mon rapport confidentiel.txt"), researcher_a, case=case_alpha
    )
    assert attachment.original_filename == "mon rapport confidentiel.txt"
    assert "confidentiel" not in attachment.storage_name
    assert "confidentiel" not in attachment.file.name
    assert attachment.storage_name.endswith(".txt")
    assert len(attachment.storage_name) > 30


def test_sha256_is_computed(case_alpha, researcher_a):
    attachment = store_attachment(upload("p.txt", b"abc"), researcher_a, case=case_alpha)
    # SHA-256 de "abc"
    assert attachment.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_upload_is_audited(case_alpha, researcher_a):
    store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    assert AuditLog.objects.filter(action=AuditAction.ATTACHMENT_UPLOADED).exists()


def test_upload_denied_outside_case_scope(case_beta, researcher_a):
    with pytest.raises(PermissionDenied):
        store_attachment(upload("p.txt"), researcher_a, case=case_beta)


def test_attachment_limit_per_case(settings, case_alpha, researcher_a):
    """La preuve jointe a la soumission compte dans la limite du dossier."""
    assert case_alpha.attachments.count() == 1
    settings.EVDP = {**settings.EVDP, "MAX_ATTACHMENTS_PER_CASE": 3}
    store_attachment(upload("a.txt"), researcher_a, case=case_alpha)
    store_attachment(upload("b.txt"), researcher_a, case=case_alpha)
    with pytest.raises(ValidationError, match="maximum"):
        store_attachment(upload("c.txt"), researcher_a, case=case_alpha)


def test_auditor_sees_metadata_but_cannot_download(client_for, case_alpha, auditor):
    """Matrice v2 : l'auditeur ne lit que les metadonnees des preuves."""
    attachment = case_alpha.attachments.get()
    response = client_for(auditor).get(reverse("attachments:download", args=[attachment.id]))
    assert response.status_code == 404


def test_dsi_downloads_only_from_step_five(client_for, case_alpha, dsi_alpha):
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance

    attachment = case_alpha.attachments.get()
    url = reverse("attachments:download", args=[attachment.id])
    client = client_for(dsi_alpha)
    advance(case_alpha, CaseStatus.VALIDATED)
    assert client.get(url).status_code == 404
    advance(case_alpha, CaseStatus.VENDOR_NOTIFIED)
    assert client.get(url).status_code == 200


# ---------------------------------------------------------------- telechargement
def test_owner_can_download(client_for, case_alpha, researcher_a):
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    client = client_for(researcher_a)
    response = client.get(reverse("attachments:download", args=[attachment.id]))
    assert response.status_code == 200
    assert response["Content-Type"] == "application/octet-stream"
    assert response["X-Content-Type-Options"] == "nosniff"


def test_unauthorized_user_gets_404_not_403(
    client_for, case_alpha, researcher_a, researcher_b
):
    """Un utilisateur sans permission ne peut pas telecharger une piece jointe."""
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    client = client_for(researcher_b)
    response = client.get(reverse("attachments:download", args=[attachment.id]))
    assert response.status_code == 404


def test_other_organization_cannot_download(client_for, case_alpha, researcher_a, dsi_beta):
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    client = client_for(dsi_beta)
    assert client.get(reverse("attachments:download", args=[attachment.id])).status_code == 404


def test_anonymous_cannot_download(client, case_alpha, researcher_a):
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    response = client.get(reverse("attachments:download", args=[attachment.id]))
    assert response.status_code == 302
    assert "/login/" in response.url


def test_download_is_audited(client_for, case_alpha, researcher_a):
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    client = client_for(researcher_a)
    client.get(reverse("attachments:download", args=[attachment.id]))
    assert AuditLog.objects.filter(action=AuditAction.ATTACHMENT_DOWNLOADED).exists()


def test_denied_download_is_audited(client_for, case_alpha, researcher_a, researcher_b):
    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    client = client_for(researcher_b)
    client.get(reverse("attachments:download", args=[attachment.id]))
    assert AuditLog.objects.filter(
        action=AuditAction.ATTACHMENT_DOWNLOADED, result="DENIED"
    ).exists()


def test_infected_file_cannot_be_downloaded(client_for, case_alpha, researcher_a):
    from apps.attachments.models import ScanStatus

    attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    attachment.scan_status = ScanStatus.INFECTED
    attachment.save(update_fields=["scan_status"])

    client = client_for(researcher_a)
    assert client.get(reverse("attachments:download", args=[attachment.id])).status_code == 404


# ------------------------------------------------ pieces jointes de message
def _internal_note_with_file(case, author):
    from apps.coordination.constants import Confidentiality
    from apps.coordination.models import CaseMessage

    note = CaseMessage.objects.create(
        case=case,
        author=author,
        body="Note d'analyse",
        confidentiality=Confidentiality.INTERNAL,
    )
    return store_attachment(upload("note-interne.txt"), author, message=note)


def test_file_of_an_internal_message_is_hidden_from_the_reporter(
    client_for, case_alpha, triager, researcher_a
):
    """Voir le dossier ne suffit pas : la piece suit le canal de son message."""
    from .conftest import claim

    attachment = _internal_note_with_file(case_alpha, claim(case_alpha, triager))
    assert attachment.case_id == case_alpha.pk

    reporter = client_for(researcher_a)
    assert (
        reporter.get(reverse("attachments:download", args=[attachment.id])).status_code == 404
    )
    page = reporter.get(reverse("coordination:case_detail", args=[case_alpha.case_id]))
    assert page.status_code == 200
    assert "note-interne.txt" not in page.content.decode()
    listing = reporter.get(f"/api/v1/reports/{case_alpha.case_id}/attachments/")
    assert listing.status_code == 200
    assert "note-interne.txt" not in {a["original_filename"] for a in listing.json()}

    assert attachment.is_visible_to(triager)
    assert attachment.is_downloadable_by(triager)
    assert not attachment.is_visible_to(researcher_a)


def test_orphan_attachment_is_visible_to_nobody(coordinator):
    from apps.attachments.models import Attachment

    orphan = Attachment.objects.create(
        original_filename="orphelin.txt", file=upload("orphelin.txt"), sha256="0" * 64
    )
    assert not orphan.is_visible_to(coordinator)
    assert not orphan.is_downloadable_by(coordinator)


# ------------------------------------------------------------ archives zip
def _zip(files, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_ordinary_zip_is_accepted():
    content = _zip({"poc.py.txt": b"print('poc')\n", "capture.log": b"GET / HTTP/1.1\n"})
    assert validate_upload(upload("preuves.zip", content))["extension"] == "zip"


def test_zip_bomb_is_rejected():
    """20 Mo de zeros tiennent en quelques Ko : taux de compression anormal."""
    content = _zip({"zeros.bin": b"\0" * (20 * 1024 * 1024)})
    assert len(content) < 100 * 1024
    with pytest.raises(ValidationError, match="bombe zip"):
        validate_upload(upload("bombe.zip", content))


def test_zip_too_large_once_decompressed_is_rejected(monkeypatch):
    from apps.attachments import services

    monkeypatch.setattr(services, "MAX_ZIP_UNCOMPRESSED_SIZE", 1024)
    content = _zip({"a.txt": b"x" * 2048}, compression=zipfile.ZIP_STORED)
    with pytest.raises(ValidationError, match="décompressée"):
        validate_upload(upload("gros.zip", content))


def test_zip_with_too_many_entries_is_rejected(monkeypatch):
    from apps.attachments import services

    monkeypatch.setattr(services, "MAX_ZIP_ENTRIES", 3)
    content = _zip({f"f{i}.txt": b"x" for i in range(4)})
    with pytest.raises(ValidationError, match="plus de 3 fichiers"):
        validate_upload(upload("nombreux.zip", content))


def test_nested_archive_is_rejected():
    """Une bombe imbriquee (42.zip) garde un taux normal a chaque niveau."""
    content = _zip({"niveau2.zip": _zip({"a.txt": b"x"}), "lisez-moi.txt": b"y"})
    with pytest.raises(ValidationError, match="d'autres archives"):
        validate_upload(upload("imbrique.zip", content))


def test_corrupted_zip_is_rejected():
    with pytest.raises(ValidationError, match="invalide ou corrompue"):
        validate_upload(upload("casse.zip", b"PK\x03\x04" + b"\0" * 64))


def test_webp_signature_is_checked():
    webp = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\0" * 32
    assert validate_upload(upload("capture.webp", webp))["extension"] == "webp"
    wav = b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\0" * 32
    with pytest.raises(ValidationError, match="signature"):
        validate_upload(upload("faux.webp", wav))


def test_pcapng_capture_is_accepted():
    pcapng = b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c\x2b\x1a" + b"\0" * 16
    assert validate_upload(upload("trafic.pcap", pcapng))["extension"] == "pcap"


# ------------------------------------------------ analyse antivirus en panne
def test_upload_survives_an_unreachable_broker(
    monkeypatch, django_capture_on_commit_callbacks, case_alpha, researcher_a
):
    """Broker injoignable : le depot aboutit, la piece reste en attente."""
    from kombu.exceptions import OperationalError

    from apps.attachments.models import ScanStatus
    from apps.attachments.tasks import scan_attachment

    def broker_down(*args, **kwargs):
        raise OperationalError("Timeout connecting to server")

    monkeypatch.setattr(scan_attachment, "apply_async", broker_down)
    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        attachment = store_attachment(upload("p.txt"), researcher_a, case=case_alpha)
    assert callbacks, "l'analyse n'a pas ete confiee a Celery"
    attachment.refresh_from_db()
    assert attachment.scan_status == ScanStatus.PENDING


def test_pending_scans_are_dispatched_again(monkeypatch, case_alpha, researcher_a):
    from datetime import timedelta

    from django.utils import timezone

    from apps.attachments import services
    from apps.attachments.models import Attachment, ScanStatus
    from apps.attachments.tasks import sweep_pending_scans

    ancienne = store_attachment(upload("a.txt"), researcher_a, case=case_alpha)
    recente = store_attachment(upload("b.txt"), researcher_a, case=case_alpha)
    Attachment.objects.filter(pk__in=[ancienne.pk, recente.pk]).update(
        scan_status=ScanStatus.PENDING
    )
    Attachment.objects.filter(pk=ancienne.pk).update(
        created_at=timezone.now() - timedelta(hours=1)
    )
    relancees = []
    monkeypatch.setattr(services, "dispatch_scan", lambda pk: relancees.append(pk) or True)

    assert sweep_pending_scans() == 1
    assert relancees == [ancienne.pk]


# ------------------------------------------------ videos, photos, .gpg
MP4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\0" * 64
HEIC = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + b"\0" * 64
WEBM = bytes.fromhex("1a45dfa3") + b"\x9f\x42\x86\x81\x01" + b"\0" * 64


def test_video_gets_its_own_size_cap(settings):
    settings.EVDP = {
        **settings.EVDP,
        "MAX_ATTACHMENT_SIZE": 100,
        "MAX_VIDEO_ATTACHMENT_SIZE": 400,
    }
    big = MP4 + b"\0" * 200
    assert validate_upload(upload("demo.mp4", big))["extension"] == "mp4"
    with pytest.raises(ValidationError, match="volumineux"):
        validate_upload(upload("capture.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 200))
    with pytest.raises(ValidationError, match="volumineux"):
        validate_upload(upload("demo.mp4", MP4 + b"\0" * 500))


@pytest.mark.parametrize(
    ("name", "content"), [("demo.mp4", MP4), ("demo.webm", WEBM), ("photo.heic", HEIC)]
)
def test_videos_and_phone_photos_are_accepted(name, content):
    assert validate_upload(upload(name, content))


@pytest.mark.parametrize(
    ("name", "content"),
    [("demo.mp4", b"pas une video" * 10), ("photo.heic", MP4), ("demo.webm", MP4)],
)
def test_renamed_files_are_refused(name, content):
    with pytest.raises(ValidationError, match="signature"):
        validate_upload(upload(name, content))


def test_binary_gpg_is_accepted_and_flagged_encrypted(case_alpha, researcher_a):
    packet = bytes([0x85, 0x01, 0x0C, 0x03]) + b"\x11" * 64
    attachment = store_attachment(
        upload("preuve.txt.gpg", packet), researcher_a, case=case_alpha
    )
    assert attachment.is_pgp_encrypted
    with pytest.raises(ValidationError, match="OpenPGP"):
        validate_upload(upload("faux.gpg", b"texte en clair renomme"))


def test_a_file_over_the_clamav_stream_limit_is_marked_not_scanned(settings):
    import io

    from apps.attachments.models import ScanStatus
    from apps.attachments.tasks import _clamav_scan

    settings.CLAMAV_HOST = "clamav.invalid"
    settings.CLAMAV_STREAM_MAX_LENGTH = 10
    status, detail = _clamav_scan(io.BytesIO(b"x" * 11), size=11)
    assert status == ScanStatus.SKIPPED
    assert "volumineux" in detail
