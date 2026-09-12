"""Validation et enregistrement securises des pieces jointes."""

import mimetypes

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core.pgp import is_encrypted_blob
from apps.core.utils import sha256_hexdigest

from .models import Attachment, ScanStatus

#: Signatures binaires refusees quel que soit le nom du fichier.
DANGEROUS_MAGIC = (
    b"MZ",  # executable Windows (PE)
    b"\x7fELF",  # executable Linux (ELF)
    b"\xca\xfe\xba\xbe",  # Java / Mach-O fat
    b"#!/",  # script shell
)

#: Signatures attendues pour les formats binaires autorises.
ALLOWED_MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "pdf": (b"%PDF-",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "pcap": (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ),
}


def _extension(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def validate_upload(uploaded_file):
    """Controle taille, extension, MIME et signature binaire.

    Leve ValidationError au premier probleme rencontre.
    """
    config = settings.EVDP
    name = (uploaded_file.name or "").strip()
    if not name:
        raise ValidationError("Nom de fichier manquant.")
    if len(name) > 255:
        raise ValidationError("Nom de fichier trop long.")

    if uploaded_file.size > config["MAX_ATTACHMENT_SIZE"]:
        limit_mb = config["MAX_ATTACHMENT_SIZE"] // (1024 * 1024)
        raise ValidationError(f"Fichier trop volumineux (maximum {limit_mb} Mo).")
    if uploaded_file.size == 0:
        raise ValidationError("Fichier vide.")

    extension = _extension(name)
    if not extension:
        raise ValidationError("Extension de fichier manquante.")
    if extension in config["ATTACHMENT_BLOCKED_EXTENSIONS"]:
        raise ValidationError(f"Extension interdite : .{extension}")
    if extension not in config["ATTACHMENT_ALLOWED_EXTENSIONS"]:
        allowed = ", ".join(sorted(config["ATTACHMENT_ALLOWED_EXTENSIONS"]))
        raise ValidationError(
            f"Extension non autorisee : .{extension}. Extensions acceptees : {allowed}."
        )

    declared = (getattr(uploaded_file, "content_type", "") or "").lower()
    guessed, _ = mimetypes.guess_type(name)
    if declared in ("application/x-msdownload", "application/x-executable"):
        raise ValidationError("Type de contenu executable refuse.")

    head = uploaded_file.read(8)
    uploaded_file.seek(0)
    for magic in DANGEROUS_MAGIC:
        if head.startswith(magic):
            raise ValidationError("Le contenu du fichier correspond a un executable : refus.")
    expected_magic = ALLOWED_MAGIC.get(extension)
    if expected_magic and not any(head.startswith(magic) for magic in expected_magic):
        raise ValidationError(
            f"La signature du fichier ne correspond pas a son extension .{extension}."
        )
    return {
        "extension": extension,
        "content_type": (guessed or declared or "application/octet-stream")[:120],
    }


def compute_digest(uploaded_file):
    uploaded_file.seek(0)
    digest = sha256_hexdigest(iter(lambda: uploaded_file.read(65536), b""))
    uploaded_file.seek(0)
    return digest


@transaction.atomic
def store_attachment(
    uploaded_file, uploader, case=None, report=None, message=None, description="", request=None
):
    """Valide puis enregistre une piece jointe rattachee a un case.

    Le fichier est ecrit sous un nom aleatoire ; le nom d'origine est conserve
    uniquement comme metadonnee d'affichage.
    """
    target_case = case or (message.case if message else None)
    if target_case is None and report is not None:
        target_case = getattr(report, "case", None)

    if target_case is not None and uploader is not None and uploader.is_authenticated:
        if not target_case.is_visible_to(uploader):
            raise PermissionDenied("Vous n'avez pas acces a ce dossier.")
        limit = settings.EVDP["MAX_ATTACHMENTS_PER_CASE"]
        if target_case.attachments.count() >= limit:
            raise ValidationError(
                f"Nombre maximum de pieces jointes atteint pour ce dossier ({limit})."
            )

    metadata = validate_upload(uploaded_file)
    digest = compute_digest(uploaded_file)

    head = uploaded_file.read(200)
    uploaded_file.seek(0)
    try:
        encrypted = is_encrypted_blob(head.decode("utf-8", errors="ignore"))
    except Exception:  # pragma: no cover
        encrypted = False

    attachment = Attachment(
        case=target_case,
        report=report,
        message=message,
        uploaded_by=uploader if getattr(uploader, "is_authenticated", False) else None,
        original_filename=uploaded_file.name[:255],
        content_type=metadata["content_type"],
        size=uploaded_file.size,
        sha256=digest,
        description=description[:255],
        is_pgp_encrypted=encrypted,
        scan_status=ScanStatus.PENDING,
    )
    attachment.save()
    attachment.file.save(attachment.storage_name, uploaded_file, save=True)

    log_action(
        AuditAction.ATTACHMENT_UPLOADED,
        actor=attachment.uploaded_by,
        obj=attachment,
        request=request,
        case=target_case.case_id if target_case else None,
        sha256=digest,
        size=attachment.size,
        filename=attachment.original_filename,
    )

    from .tasks import scan_attachment

    transaction.on_commit(lambda: scan_attachment.delay(str(attachment.pk)))
    return attachment


def authorize_download(attachment, user, request=None):
    """Autorise (ou refuse) le telechargement et journalise l'acces."""
    if not attachment.is_visible_to(user):
        log_action(
            AuditAction.ATTACHMENT_DOWNLOADED,
            actor=user,
            obj=attachment,
            result="DENIED",
            request=request,
        )
        raise PermissionDenied("Vous n'avez pas acces a cette piece jointe.")
    if not attachment.is_downloadable:
        raise PermissionDenied(
            "Ce fichier est bloque : une analyse antivirus l'a signale comme infecte."
        )
    Attachment.objects.filter(pk=attachment.pk).update(
        download_count=attachment.download_count + 1
    )
    log_action(
        AuditAction.ATTACHMENT_DOWNLOADED,
        actor=user,
        obj=attachment,
        request=request,
        case=attachment.owning_case().case_id if attachment.owning_case() else None,
        sha256=attachment.sha256,
    )
    return True
