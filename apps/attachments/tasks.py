"""Taches asynchrones liees aux pieces jointes."""

import logging
import socket
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from .models import Attachment, ScanStatus

logger = logging.getLogger("evdp.attachments")


#: Taille des morceaux envoyes a ClamAV : le fichier n'est jamais charge en
#: entier en memoire (une video peut peser 200 Mo, le worker bien moins).
CHUNK_SIZE = 64 * 1024


def _clamav_scan(handle, size=0):
    """Analyse via un service ClamAV (protocole INSTREAM), par morceaux.

    Le service est optionnel : s'il est absent, le fichier est marque SKIPPED
    et reste telechargeable, mais l'absence d'analyse est tracee. Un fichier
    plus gros que la limite de flux de clamd (StreamMaxLength) n'est pas
    envoye : clamd couperait la connexion en cours d'envoi, ce qui se lirait
    a tort comme un antivirus injoignable.
    """
    host = getattr(settings, "CLAMAV_HOST", None) or ""
    port = int(getattr(settings, "CLAMAV_PORT", 3310))
    if not host:
        return ScanStatus.SKIPPED, "Service ClamAV non configuré."
    if size > settings.CLAMAV_STREAM_MAX_LENGTH:
        return ScanStatus.SKIPPED, "Fichier trop volumineux pour l'antivirus (non analysé)."

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(b"zINSTREAM\0")

            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)

            sock.sendall((0).to_bytes(4, "big"))

            response = sock.recv(4096).decode("utf-8", errors="ignore")
            response = response.replace("\x00", "").strip()[:255]

        if "OK" in response and "FOUND" not in response:
            return ScanStatus.CLEAN, response

        if "FOUND" in response:
            return ScanStatus.INFECTED, response

        if "size limit exceeded" in response.lower():
            # Au-dela de StreamMaxLength (25 Mo par defaut) : non analyse.
            return (
                ScanStatus.SKIPPED,
                "Fichier trop volumineux pour l'antivirus (non analysé).",
            )

        return ScanStatus.ERROR, response

    except OSError as exc:
        return ScanStatus.ERROR, f"ClamAV injoignable: {exc}"[:255]


# ignore_result : le verdict est ecrit sur la piece. Stocker un resultat
# Celery abonnait l'appelant au backend Redis, qui retentait 20 fois la
# connexion (plus d'une minute) si Redis etait indisponible.
@shared_task(name="apps.attachments.tasks.scan_attachment", ignore_result=True)
def scan_attachment(attachment_id):
    """Analyse antivirus d'une piece jointe (service optionnel)."""
    attachment = Attachment.objects.filter(pk=attachment_id).first()
    if attachment is None:
        return "not-found"
    try:
        with attachment.file.open("rb") as handle:
            status, detail = _clamav_scan(handle, attachment.size)
    except Exception as exc:  # pragma: no cover
        attachment.scan_status = ScanStatus.ERROR
        attachment.scan_detail = str(exc)[:255]
        attachment.save(update_fields=["scan_status", "scan_detail", "updated_at"])
        return "read-error"

    attachment.scan_status = status
    attachment.scan_detail = detail
    attachment.save(update_fields=["scan_status", "scan_detail", "updated_at"])
    if status == ScanStatus.INFECTED:
        logger.warning(
            "attachment_infected",
            extra={"attachment": str(attachment.pk), "detail": detail},
        )
    return status


#: Delai au-dela duquel une analyse encore en attente est relancee : l'envoi
#: initial a pu echouer (broker indisponible au moment du depot).
PENDING_SCAN_GRACE = timedelta(minutes=10)


@shared_task(name="apps.attachments.tasks.sweep_pending_scans", ignore_result=True)
def sweep_pending_scans():
    """Relance l'analyse des pieces restees PENDING."""
    from .services import dispatch_scan

    cutoff = timezone.now() - PENDING_SCAN_GRACE
    pending = Attachment.objects.filter(scan_status=ScanStatus.PENDING, created_at__lt=cutoff)
    return sum(dispatch_scan(pk) for pk in pending.values_list("pk", flat=True))
