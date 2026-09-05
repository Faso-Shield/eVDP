"""Telechargement controle des pieces jointes.

Aucun fichier n'est servi directement par Nginx : chaque acces passe par
cette vue qui verifie les droits sur le case et journalise l'operation.
"""

import re

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404

from .models import Attachment
from .services import authorize_download

_UNSAFE = re.compile(r"[^A-Za-z0-9._\- ]")


def safe_filename(name):
    """Nom propose au navigateur, debarrasse de tout caractere de controle."""
    cleaned = _UNSAFE.sub("_", (name or "fichier").strip())[:120]
    return cleaned or "fichier"


@login_required
def download(request, attachment_id):
    attachment = get_object_or_404(Attachment, pk=attachment_id)
    try:
        authorize_download(attachment, request.user, request=request)
    except PermissionDenied as exc:
        # On ne confirme jamais l'existence d'un fichier hors perimetre.
        raise Http404("Fichier introuvable.") from exc

    response = FileResponse(
        attachment.file.open("rb"),
        as_attachment=True,
        filename=safe_filename(attachment.original_filename),
        # Type generique : le navigateur ne doit jamais interpreter le contenu.
        content_type="application/octet-stream",
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response["Cache-Control"] = "no-store, private"
    return response
