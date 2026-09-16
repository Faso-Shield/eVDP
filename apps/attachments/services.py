"""Validation et enregistrement securises des pieces jointes."""

import logging
import mimetypes
import zipfile

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core.pgp import is_encrypted_blob
from apps.core.utils import sha256_hexdigest

from .models import Attachment, ScanStatus

logger = logging.getLogger("evdp.security")

#: Signatures binaires refusees quel que soit le nom du fichier.
DANGEROUS_MAGIC = (
    b"MZ",  # executable Windows (PE)
    b"\x7fELF",  # executable Linux (ELF)
    b"\xca\xfe\xba\xbe",  # class Java / Mach-O fat
    b"#!/",  # script shell
)

#: Limites anti "bombe zip" : nombre d'entrees, taille decompressee totale,
#: et ratio de compression maximal avant suspicion.
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED_SIZE = 200 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100


def _extension(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def _signature_matches(extension, head):
    """Verification positive : le contenu correspond-il vraiment a
    l'extension declaree ? None si ce type n'a pas de signature fiable
    (formats texte : txt, md, json, csv, xml, yaml, log, eml, asc, pgp)."""
    if extension in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if extension == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if extension == "gif":
        return head.startswith((b"GIF87a", b"GIF89a"))
    if extension == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if extension in ("heic", "heif"):
        # Conteneur ISOBMFF (comme le MP4) : boite "ftyp" en octet 4, puis une
        # marque identifiant le format. De nombreux telephones Android et tous
        # les iPhone recents enregistrent les photos dans ce format par defaut.
        return head[4:8] == b"ftyp" and head[8:12] in (
            b"heic", b"heix", b"heim", b"heis",
            b"hevc", b"hevx", b"hevm", b"hevs",
            b"mif1", b"msf1",
        )
    if extension == "pdf":
        return head.startswith(b"%PDF-")
    if extension == "zip":
        return head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    if extension == "pcap":
        return head[:4] in (
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\xc3\xb2\xa1",
            b"\x0a\x0d\x0d\x0a",  # pcapng
        )
    return None


def _validate_zip_safety(uploaded_file):
    """Rejette une archive ZIP trop grande, trop peuplee, ou dont le taux de
    compression suggere une bombe zip (compression bomb)."""
    uploaded_file.seek(0)
    try:
        with zipfile.ZipFile(uploaded_file) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ValidationError(
                    f"Archive ZIP refusee : plus de {MAX_ZIP_ENTRIES} fichiers contenus."
                )
            total_uncompressed = sum(info.file_size for info in infos)
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED_SIZE:
                raise ValidationError(
                    "Archive ZIP refusee : contenu decompresse trop volumineux."
                )
            total_compressed = sum(info.compress_size for info in infos) or 1
            if total_uncompressed / total_compressed > MAX_ZIP_COMPRESSION_RATIO:
                raise ValidationError(
                    "Archive ZIP refusee : taux de compression anormal (bombe zip suspectee)."
                )
    except zipfile.BadZipFile as exc:
        raise ValidationError("Fichier ZIP invalide ou corrompu.") from exc
    finally:
        uploaded_file.seek(0)


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

    head = uploaded_file.read(16)
    uploaded_file.seek(0)
    for magic in DANGEROUS_MAGIC:
        if head.startswith(magic):
            raise ValidationError("Le contenu du fichier correspond a un executable : refus.")

    # Verification positive : le contenu doit correspondre a l'extension
    # declaree pour les types qui ont une signature binaire fiable (les
    # formats texte n'en ont pas et passent sans etre bloques ici).
    if _signature_matches(extension, head) is False:
        raise ValidationError(
            f"Le contenu du fichier ne correspond pas a son extension declaree (.{extension})."
        )
    if extension == "zip":
        _validate_zip_safety(uploaded_file)

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

    if target_case is not None:
        # Le quota s'applique inconditionnellement, y compris pour un
        # televersement non authentifie (formulaire public) : ce n'est pas
        # une verification de droits, seulement une limite anti-abus par
        # dossier, qui ne doit donc pas dependre du statut d'authentification.
        limit = settings.EVDP["MAX_ATTACHMENTS_PER_CASE"]
        if target_case.attachments.count() >= limit:
            raise ValidationError(
                f"Nombre maximum de pieces jointes atteint pour ce dossier ({limit})."
            )
        if uploader is not None and uploader.is_authenticated:
            if not target_case.is_visible_to(uploader):
                raise PermissionDenied("Vous n'avez pas acces a ce dossier.")

    metadata = validate_upload(uploaded_file)
    digest = compute_digest(uploaded_file)

    # Un bloc PGP armure porte son en-tete au tout debut du fichier mais son
    # pied de page (et le checksum qui le precede) seulement a la toute fin :
    # les deux doivent etre verifies pour ne pas rater un fichier legitimement
    # chiffre (voir apps/core/pgp.is_encrypted_blob). On lit un echantillon
    # borne a chaque extremite plutot que le fichier entier, pour rester
    # efficace meme sur une piece jointe volumineuse.
    sample_size = 4096
    uploaded_file.seek(0)
    head = uploaded_file.read(sample_size)
    tail = b""
    if uploaded_file.size > sample_size:
        uploaded_file.seek(max(uploaded_file.size - sample_size, 0))
        tail = uploaded_file.read(sample_size)
    uploaded_file.seek(0)
    try:
        sample_text = (head + tail).decode("utf-8", errors="ignore")
        encrypted = is_encrypted_blob(sample_text)
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

    transaction.on_commit(lambda: _dispatch_scan(attachment.pk))
    return attachment


def _dispatch_scan(attachment_id):
    """Met en file l'analyse antivirus, sans jamais bloquer l'appelant.

    Si le broker (Redis) est momentanement injoignable, la mise en file
    echoue en quelques centaines de ms (au lieu des ~20 tentatives de
    reconnexion par defaut de Celery, qui pourraient geler la reponse HTTP
    pendant plusieurs dizaines de secondes). La piece jointe reste
    consultable ; scan_status demeure PENDING et sera repris via une
    nouvelle tentative de scan (cf. gestion manuelle ou sweep futur).
    """
    from .tasks import scan_attachment

    try:
        scan_attachment.apply_async(
            args=[str(attachment_id)],
            retry=True,
            retry_policy={
                "max_retries": 1,
                "interval_start": 0,
                "interval_step": 0.2,
                "interval_max": 0.2,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "attachment_scan_dispatch_failed",
            extra={"attachment": str(attachment_id), "error": exc.__class__.__name__},
        )


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
