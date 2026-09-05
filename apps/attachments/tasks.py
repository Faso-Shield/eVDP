"""Taches asynchrones liees aux pieces jointes."""

import logging
import socket

from celery import shared_task
from django.conf import settings

from .models import Attachment, ScanStatus

logger = logging.getLogger("evdp.attachments")


def _clamav_scan(data):
    """Analyse via un service ClamAV (protocole INSTREAM).

    Le service est optionnel : s'il est absent, le fichier est marque SKIPPED
    et reste telechargeable, mais l'absence d'analyse est tracee.
    """
    host = getattr(settings, "CLAMAV_HOST", None) or ""
    port = int(getattr(settings, "CLAMAV_PORT", 3310))
    if not host:
        return ScanStatus.SKIPPED, "Service ClamAV non configure."
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), 8192):
                chunk = data[offset : offset + 8192]
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
            sock.sendall((0).to_bytes(4, "big"))
            response = sock.recv(4096).decode("utf-8", errors="ignore")
        if "OK" in response and "FOUND" not in response:
            return ScanStatus.CLEAN, response.strip()[:255]
        if "FOUND" in response:
            return ScanStatus.INFECTED, response.strip()[:255]
        return ScanStatus.ERROR, response.strip()[:255]
    except OSError as exc:
        return ScanStatus.ERROR, f"ClamAV injoignable: {exc}"[:255]


@shared_task(name="apps.attachments.tasks.scan_attachment")
def scan_attachment(attachment_id):
    """Analyse antivirus d'une piece jointe (service optionnel)."""
    attachment = Attachment.objects.filter(pk=attachment_id).first()
    if attachment is None:
        return "not-found"
    try:
        with attachment.file.open("rb") as handle:
            data = handle.read()
    except Exception as exc:  # pragma: no cover
        attachment.scan_status = ScanStatus.ERROR
        attachment.scan_detail = str(exc)[:255]
        attachment.save(update_fields=["scan_status", "scan_detail", "updated_at"])
        return "read-error"

    status, detail = _clamav_scan(data)
    attachment.scan_status = status
    attachment.scan_detail = detail
    attachment.save(update_fields=["scan_status", "scan_detail", "updated_at"])
    if status == ScanStatus.INFECTED:
        logger.warning(
            "attachment_infected",
            extra={"attachment": str(attachment.pk), "detail": detail},
        )
    return status
