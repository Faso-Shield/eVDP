"""Tests des pieces jointes : validation, isolation, tracabilite."""

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
    with pytest.raises(ValidationError, match="non autorisee"):
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
    with pytest.raises(ValidationError, match="executable"):
        validate_upload(upload("innocent.txt", b"MZ\x90\x00\x03binaire"))


def test_elf_content_is_rejected():
    with pytest.raises(ValidationError, match="executable"):
        validate_upload(upload("innocent.log", b"\x7fELF\x02\x01binaire"))


def test_shell_script_content_is_rejected():
    with pytest.raises(ValidationError, match="executable"):
        validate_upload(upload("notes.txt", b"#!/bin/sh\nrm -rf /"))


# ------------------------------------------------------- signature positive
def test_png_with_real_png_signature_is_accepted():
    content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    metadata = validate_upload(upload("capture.png", content))
    assert metadata["extension"] == "png"


def test_png_extension_with_mismatched_content_is_rejected():
    """Regression : la verification de signature n'etait qu'une liste noire
    d'executables, jamais une correspondance positive avec l'extension."""
    with pytest.raises(ValidationError, match="ne correspond pas"):
        validate_upload(upload("capture.png", b"ceci n'est pas une image PNG du tout"))


def test_pdf_with_real_pdf_signature_is_accepted():
    content = b"%PDF-1.7\n" + b"\x00" * 32
    metadata = validate_upload(upload("rapport.pdf", content))
    assert metadata["extension"] == "pdf"


def test_pdf_extension_with_mismatched_content_is_rejected():
    with pytest.raises(ValidationError, match="ne correspond pas"):
        validate_upload(upload("rapport.pdf", b"pas du tout un PDF"))


def test_gif_with_real_signature_is_accepted():
    metadata = validate_upload(upload("anim.gif", b"GIF89a" + b"\x00" * 32))
    assert metadata["extension"] == "gif"


def test_webp_with_real_signature_is_accepted():
    content = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 16
    metadata = validate_upload(upload("photo.webp", content))
    assert metadata["extension"] == "webp"


def test_heic_with_real_signature_is_accepted():
    """Format par defaut de l'appareil photo de nombreux telephones."""
    content = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 32
    metadata = validate_upload(upload("photo.heic", content))
    assert metadata["extension"] == "heic"


def test_heif_with_generic_mif1_brand_is_accepted():
    content = b"\x00\x00\x00\x18ftypmif1" + b"\x00" * 32
    metadata = validate_upload(upload("photo.heif", content))
    assert metadata["extension"] == "heif"


def test_heic_extension_with_mismatched_content_is_rejected():
    with pytest.raises(ValidationError, match="ne correspond pas"):
        validate_upload(upload("photo.heic", b"ceci n'est pas un fichier HEIC"))


def test_text_formats_have_no_signature_requirement():
    """Les formats texte (txt, md, json, csv...) n'ont pas de signature
    binaire fiable : aucune verification positive ne doit les bloquer."""
    for name, content in [
        ("notes.md", b"# Titre\n\nContenu Markdown."),
        ("data.json", b'{"cle": "valeur"}'),
        ("export.csv", b"colonne1,colonne2\nvaleur1,valeur2"),
    ]:
        metadata = validate_upload(upload(name, content))
        assert metadata["extension"] == name.rsplit(".", 1)[1]


# --------------------------------------------------------------- zip / bombe
def _build_zip(entries, compression=None):
    import io
    import zipfile as zf

    buffer = io.BytesIO()
    with zf.ZipFile(buffer, "w", compression or zf.ZIP_DEFLATED) as archive:
        for entry_name, entry_content in entries:
            archive.writestr(entry_name, entry_content)
    buffer.seek(0)
    return buffer.read()


def test_normal_zip_is_accepted():
    content = _build_zip([("readme.txt", b"contenu normal de preuve")])
    metadata = validate_upload(upload("preuve.zip", content))
    assert metadata["extension"] == "zip"


def test_zip_with_mismatched_content_is_rejected():
    with pytest.raises(ValidationError, match="ne correspond pas"):
        validate_upload(upload("preuve.zip", b"pas une archive ZIP"))


def test_zip_with_too_many_entries_is_rejected():
    from apps.attachments.services import MAX_ZIP_ENTRIES

    entries = [(f"fichier-{i}.txt", b"x") for i in range(MAX_ZIP_ENTRIES + 1)]
    content = _build_zip(entries)
    with pytest.raises(ValidationError, match="ZIP refusee"):
        validate_upload(upload("gros.zip", content))


def test_zip_bomb_like_compression_ratio_is_rejected():
    """Un seul fichier hautement compressible (ex. des zeros repetes) peut
    gonfler de facon disproportionnee une fois decompresse : c'est le
    principe d'une bombe zip."""
    import io
    import zipfile as zf

    buffer = io.BytesIO()
    with zf.ZipFile(buffer, "w", zf.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("zeros.bin", b"\x00" * (5 * 1024 * 1024))
    content = buffer.getvalue()
    with pytest.raises(ValidationError, match="ZIP refusee"):
        validate_upload(upload("suspect.zip", content))


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


def test_pgp_encrypted_attachment_is_detected_even_when_large(case_alpha, researcher_a):
    """Regression : le pied de page d'un bloc PGP arme se trouve en fin de
    fichier, jamais dans les tout premiers octets pour un contenu de taille
    normale -- la detection doit verifier les deux extremites du fichier,
    pas seulement son debut."""
    padding = "x" * 5000
    content = (
        f"-----BEGIN PGP MESSAGE-----\n\n{padding}\n-----END PGP MESSAGE-----\n"
    ).encode()
    attachment = store_attachment(upload("preuve.txt", content), researcher_a, case=case_alpha)
    assert attachment.is_pgp_encrypted is True


def test_non_encrypted_attachment_is_not_flagged(case_alpha, researcher_a):
    attachment = store_attachment(
        upload("p.txt", b"contenu tout a fait normal"), researcher_a, case=case_alpha
    )
    assert attachment.is_pgp_encrypted is False


def test_upload_denied_outside_case_scope(case_beta, researcher_a):
    with pytest.raises(PermissionDenied):
        store_attachment(upload("p.txt"), researcher_a, case=case_beta)


def test_attachment_limit_per_case(settings, case_alpha, researcher_a):
    settings.EVDP = {**settings.EVDP, "MAX_ATTACHMENTS_PER_CASE": 2}
    store_attachment(upload("a.txt"), researcher_a, case=case_alpha)
    store_attachment(upload("b.txt"), researcher_a, case=case_alpha)
    with pytest.raises(ValidationError, match="maximum"):
        store_attachment(upload("c.txt"), researcher_a, case=case_alpha)


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
