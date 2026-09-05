"""Gestion des erreurs de l'API.

Les messages restent neutres : ils ne doivent jamais reveler l'existence
d'une ressource a laquelle l'appelant n'a pas acces.
"""

import logging

from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import exception_handler

logger = logging.getLogger("evdp.api")


def evdp_exception_handler(exc, context):
    if isinstance(exc, DjangoValidationError):
        exc = exceptions.ValidationError(
            getattr(exc, "message_dict", None) or list(exc.messages)
        )

    response = exception_handler(exc, context)

    if response is None:
        logger.exception("api_unhandled_error", extra={"view": str(context.get("view"))})
        return Response(
            {"detail": "Erreur interne du serveur."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Un 403 sur une ressource privee est presente comme un 404 : ne pas
    # confirmer l'existence d'un case a un utilisateur non autorise.
    if isinstance(exc, (PermissionDenied, exceptions.PermissionDenied)) and context.get(
        "kwargs"
    ):
        response.status_code = status.HTTP_404_NOT_FOUND
        response.data = {"detail": "Ressource introuvable."}
    elif isinstance(exc, Http404):
        response.data = {"detail": "Ressource introuvable."}

    return response
