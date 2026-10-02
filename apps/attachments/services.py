"""Validation et enregistrement securises des pieces jointes."""

import logging
import mimetypes
import zipfile

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core.pgp import is_binary_encrypted, is_encrypted_blob
from apps.core.utils import sha256_hexdigest

from .models import Attachment, ScanStatus

logger = logging.getLogger("evdp.attachments")

#: Une seule reprise rapide : l'envoi a lieu pendant la requete HTTP du
#: deposant, une panne du broker ne doit pas la faire attendre.
SCAN_PUBLISH_RETRY_POLICY = {
    "max_retries": 1,
    "interval_start": 0,
    "interval_step": 0.2,
    "interval_max": 0.2,
}

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
        b"\x0a\x0d\x0d\x0a",  # pcapng, format par defaut de Wireshark
    ),
}

#: Signatures verifiees au-dela du debut du fichier : (decalage, octets).
#: Le webp commence par "RIFF", commun a d'autres formats (wav, avi) ; seule
#: la marque "WEBP" en octet 8 l'identifie. mp4, heic et heif sont des
#: conteneurs ISOBMFF : boite "ftyp" en octet 4.
ALLOWED_MAGIC_AT = {
    "webp": ((0, b"RIFF"), (8, b"WEBP")),
    "mp4": ((4, b"ftyp"),),
    "heic": ((4, b"ftyp"),),
    "heif": ((4, b"ftyp"),),
    # En-tete EBML (Matroska / WebM).
    "webm": ((0, bytes.fromhex("1a45dfa3")),),
}

#: Marques ISOBMFF d'une image HEIF/HEIC (octets 8 a 12). Un mp4 renomme en
#: .heic porte une autre marque.
HEIF_BRANDS = frozenset(
    {b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx", b"hevm", b"hevs", b"mif1", b"msf1"}
)

#: Limites anti "bombe zip". Le serveur ne decompresse jamais une archive,
#: mais l'analyste qui l'ouvre et l'antivirus, si : on refuse celles qui
#: exploseraient a l'ouverture.
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED_SIZE = 200 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 100
NESTED_ARCHIVE_EXTENSIONS = ("zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "tar", "jar")


def _extension(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def _check_zip_safety(uploaded_file):
    """Refuse une archive trop peuplee, trop grosse une fois decompressee, au
    taux de compression anormal, ou contenant d'autres archives.

    Les tailles lues sont celles que declare l'archive ; une bombe imbriquee
    ("42.zip") garde un taux normal a chaque niveau, d'ou le refus des
    archives dans l'archive.
    """
    uploaded_file.seek(0)
    try:
        with zipfile.ZipFile(uploaded_file) as archive:
            entries = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError) as exc:
        raise ValidationError("Archive ZIP invalide ou corrompue.") from exc
    finally:
        uploaded_file.seek(0)

    if len(entries) > MAX_ZIP_ENTRIES:
        raise ValidationError(f"Archive refusée : plus de {MAX_ZIP_ENTRIES} fichiers.")
    uncompressed = sum(entry.file_size for entry in entries)
    if uncompressed > MAX_ZIP_UNCOMPRESSED_SIZE:
        limit_mb = MAX_ZIP_UNCOMPRESSED_SIZE // (1024 * 1024)
        raise ValidationError(
            f"Archive refusée : plus de {limit_mb} Mo une fois décompressée."
        )
    compressed = sum(entry.compress_size for entry in entries) or 1
    if uncompressed / compressed > MAX_ZIP_COMPRESSION_RATIO:
        raise ValidationError("Archive refusée : taux de compression anormal (bombe zip).")
    if any(_extension(entry.filename) in NESTED_ARCHIVE_EXTENSIONS for entry in entries):
        raise ValidationError(
            "Archive refusée : elle contient d'autres archives. "
            "Joignez les fichiers directement ou dans une seule archive."
        )


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
            f"Extension non autorisée : .{extension}. Extensions acceptées : {allowed}."
        )
    # Plafond selon le type : une video a le sien, plus eleve.
    limit = (
        config["MAX_VIDEO_ATTACHMENT_SIZE"]
        if extension in config.get("ATTACHMENT_VIDEO_EXTENSIONS", ())
        else config["MAX_ATTACHMENT_SIZE"]
    )
    if uploaded_file.size > limit:
        raise ValidationError(
            f"Fichier trop volumineux (maximum {limit // (1024 * 1024)} Mo)."
        )

    declared = (getattr(uploaded_file, "content_type", "") or "").lower()
    guessed, _ = mimetypes.guess_type(name)
    if declared in ("application/x-msdownload", "application/x-executable"):
        raise ValidationError("Type de contenu exécutable refusé.")

    head = uploaded_file.read(16)
    uploaded_file.seek(0)
    for magic in DANGEROUS_MAGIC:
        if head.startswith(magic):
            raise ValidationError("Le contenu du fichier correspond à un exécutable : refus.")

    # Verification positive : le contenu doit correspondre a l'extension
    # declaree. Refuser les signatures dangereuses ne suffit pas - un
    # format binaire inconnu du premier controle passait sous une extension
    # anodine. Les formats texte n'ont pas de signature fiable et ne sont
    # donc pas listes ici.
    expected_magic = ALLOWED_MAGIC.get(extension)
    expected_at = ALLOWED_MAGIC_AT.get(extension, ())
    if (expected_magic and not any(head.startswith(magic) for magic in expected_magic)) or any(
        head[offset : offset + len(magic)] != magic for offset, magic in expected_at
    ):
        raise ValidationError(
            f"La signature du fichier ne correspond pas à son extension .{extension}."
        )
    if extension in ("heic", "heif") and head[8:12] not in HEIF_BRANDS:
        raise ValidationError(
            f"La signature du fichier ne correspond pas à son extension .{extension}."
        )
    if extension == "gpg" and not (
        is_binary_encrypted(head) or head.startswith(b"-----BEGIN PGP MESSAGE")
    ):
        raise ValidationError("Un fichier .gpg doit être un message OpenPGP chiffré.")
    if extension == "zip":
        _check_zip_safety(uploaded_file)

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
            raise PermissionDenied("Vous n'avez pas accès à ce dossier.")
        limit = settings.EVDP["MAX_ATTACHMENTS_PER_CASE"]
        if target_case.attachments.count() >= limit:
            raise ValidationError(
                f"Nombre maximum de pièces jointes atteint pour ce dossier ({limit})."
            )

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
        encrypted = is_encrypted_blob(sample_text) or (
            metadata["extension"] in ("gpg", "pgp") and is_binary_encrypted(head)
        )
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

    transaction.on_commit(lambda: dispatch_scan(attachment.pk))
    return attachment


def dispatch_scan(attachment_id):
    """Confie l'analyse antivirus a Celery, sans jamais faire echouer l'appel.

    Broker injoignable : la piece reste PENDING et sweep_pending_scans la
    reprend plus tard. Le depot, lui, est deja enregistre et journalise.
    """
    from .tasks import scan_attachment

    try:
        scan_attachment.apply_async(
            args=[str(attachment_id)], retry=True, retry_policy=SCAN_PUBLISH_RETRY_POLICY
        )
    except Exception:
        logger.warning(
            "attachment_scan_dispatch_failed",
            extra={"attachment": str(attachment_id)},
            exc_info=True,
        )
        return False
    return True


def authorize_download(attachment, user, request=None):
    """Autorise (ou refuse) le telechargement et journalise l'acces."""
    if not attachment.is_downloadable_by(user):
        log_action(
            AuditAction.ATTACHMENT_DOWNLOADED,
            actor=user,
            obj=attachment,
            result="DENIED",
            request=request,
        )
        raise PermissionDenied("Vous n'avez pas accès à cette pièce jointe.")
    if not attachment.is_downloadable:
        raise PermissionDenied(
            "Ce fichier est bloqué : une analyse antivirus l'a signalé comme infecté."
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
