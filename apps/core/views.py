"""Pages publiques institutionnelles et sondes d'observabilite."""

import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import connection, transaction
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.core import pgp
from apps.core.markdown_utils import render_markdown
from apps.core.models import SiteSetting


def home(request):
    from apps.disclosures.models import Advisory
    from apps.programs.models import Program

    stats = _public_statistics()
    context = {
        "advisories": Advisory.objects.published()[:5],
        "programs": Program.objects.public()[:4],
        "stats": stats,
    }
    return render(request, "core/home.html", context)


def about(request):
    body = SiteSetting.get_value(
        "about",
        "eVDP est la plateforme nationale de divulgation coordonnée de "
        "vulnérabilités et de gestion des programmes Bug Bounty.",
    )
    return render(
        request,
        "core/page.html",
        {"page_title": "À propos", "body": render_markdown(body)},
    )


def disclosure_policy(request):
    body = SiteSetting.get_value("disclosure_policy", DEFAULT_DISCLOSURE_POLICY)
    return render(
        request,
        "core/disclosure_policy.html",
        {
            "page_title": "Politique de divulgation",
            "body": render_markdown(body),
            "pgp_key": pgp.national_public_key(),
            "pgp_fingerprint": pgp.national_fingerprint(),
            "pgp_active": pgp.active_national_key(),
        },
    )


@login_required
@require_capability(Capability.MANAGE_PGP_KEYS)
def pgp_key_manage(request):
    """Generation, publication et remise de la cle nationale.

    La paire est generee dans le navigateur du gestionnaire (static/js/pgp.js) :
    seule la cle publique est envoyee ici pour publication.
    """
    from .models import NationalPGPKey, PGPKeyDelivery

    if request.method == "POST" and not getattr(request.user, "is_read_only", False):
        try:
            key = pgp.publish_national_key(request.POST.get("public_key", ""), request.user)
        except pgp.PGPError as exc:
            messages.error(request, str(exc))
        else:
            log_action(
                AuditAction.PGP_KEY_PUBLISHED,
                actor=request.user,
                obj=key,
                request=request,
                fingerprint=key.fingerprint,
                expires_at=key.expires_at.isoformat() if key.expires_at else None,
            )
            messages.success(request, f"Clé publiée : {key.readable_fingerprint}.")
            return redirect("core:pgp_key_manage")
    active = pgp.active_national_key()
    return render(
        request,
        "core/pgp_key_manage.html",
        {
            "active": active,
            "history": NationalPGPKey.objects.filter(is_active=False)[:20],
            "env_fallback": not active and bool(pgp.national_public_key()),
            "expiry_warning_days": pgp.EXPIRY_WARNING_DAYS,
            "recipients": pgp.delivery_recipients() if active else [],
            "deliveries": PGPKeyDelivery.objects.select_related("recipient", "created_by")[
                :30
            ],
            "delivery_ttl_hours": pgp.DELIVERY_TTL_HOURS,
            "default_identity": {
                "name": settings.EVDP["NATIONAL_TEAM"],
                "email": settings.EVDP["CONTACT_EMAIL"],
            },
        },
    )


@login_required
@require_capability(Capability.MANAGE_PGP_KEYS)
@require_not_read_only
@require_POST
def pgp_delivery_create(request):
    """Enregistre la cle privee chiffree par le navigateur pour un destinataire."""
    from apps.accounts.models import User
    from apps.notifications.models import NotificationKind
    from apps.notifications.services import notify

    recipient = User.objects.filter(pk=_uuid_or_none(request.POST.get("recipient"))).first()
    try:
        delivery = pgp.create_key_delivery(
            request.POST.get("payload", ""), recipient, request.user
        )
    except pgp.PGPError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    log_action(
        AuditAction.PGP_KEY_DELIVERY_CREATED,
        actor=request.user,
        obj=delivery,
        request=request,
        recipient=str(recipient.pk),
        fingerprint=delivery.fingerprint,
    )
    expires = f"{timezone.localtime(delivery.expires_at):%d/%m/%Y à %H:%M}"
    notify(
        recipient,
        NotificationKind.ACCOUNT,
        title="Clé PGP nationale à récupérer",
        body=(
            f"{request.user} vous remet la clé privée nationale. Récupérez-la avant le "
            f"{expires} avec le code de remise qui vous sera communiqué par un autre canal."
        ),
        url=reverse("core:pgp_delivery_retrieve", args=[delivery.pk]),
    )
    return JsonResponse({"recipient": str(recipient), "expires_at": expires})


@login_required
@require_capability(Capability.MANAGE_PGP_KEYS)
@require_not_read_only
@require_POST
def pgp_delivery_revoke(request, delivery_id):
    from .models import PGPKeyDelivery

    delivery = get_object_or_404(PGPKeyDelivery, pk=delivery_id)
    if delivery.is_open:
        delivery.wipe(revoked_at=timezone.now())
        log_action(
            AuditAction.PGP_KEY_DELIVERY_REVOKED,
            actor=request.user,
            obj=delivery,
            request=request,
            recipient=str(delivery.recipient_id),
        )
        messages.success(request, f"Remise à {delivery.recipient} annulée et effacée.")
    return redirect("core:pgp_key_manage")


def _uuid_or_none(value):
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def _own_delivery(request, delivery_id, lock=False):
    """Remise du compte connecte, encore autorise a la recevoir (404 sinon)."""
    from .models import PGPKeyDelivery

    deliveries = PGPKeyDelivery.objects.select_related("created_by")
    if lock:
        deliveries = deliveries.select_for_update(of=("self",))
    delivery = get_object_or_404(deliveries, pk=delivery_id, recipient=request.user)
    if not pgp.delivery_recipients().filter(pk=request.user.pk).exists():
        raise Http404
    return delivery


@login_required
@never_cache
def pgp_delivery_retrieve(request, delivery_id):
    """Page du destinataire : il y saisit le code de remise."""
    delivery = _own_delivery(request, delivery_id)
    return render(
        request,
        "core/pgp_delivery_retrieve.html",
        {"delivery": delivery, "max_fetches": pgp.DELIVERY_MAX_FETCHES},
    )


@login_required
@never_cache
@require_POST
def pgp_delivery_fetch(request, delivery_id):
    """Rend le bloc chiffre ; il est efface apres DELIVERY_MAX_FETCHES essais."""
    with transaction.atomic():
        delivery = _own_delivery(request, delivery_id, lock=True)
        if not delivery.is_open:
            return JsonResponse({"error": "Cette remise n'est plus disponible."}, status=410)
        if delivery.fetch_count >= pgp.DELIVERY_MAX_FETCHES:
            delivery.wipe()
            return JsonResponse(
                {
                    "error": "Trop d'essais : la remise a été effacée. Demandez-en une nouvelle."
                },
                status=410,
            )
        delivery.fetch_count += 1
        delivery.save(update_fields=["fetch_count", "updated_at"])
    return JsonResponse(
        {
            "payload": delivery.payload,
            "fingerprint": delivery.fingerprint,
            "remaining": pgp.DELIVERY_MAX_FETCHES - delivery.fetch_count,
        }
    )


@login_required
@never_cache
@require_POST
def pgp_delivery_confirm(request, delivery_id):
    """Le navigateur a dechiffre la cle : le bloc est efface."""
    from apps.notifications.models import NotificationKind
    from apps.notifications.services import notify

    with transaction.atomic():
        delivery = _own_delivery(request, delivery_id, lock=True)
        if not delivery.is_open:
            return JsonResponse({"error": "Cette remise n'est plus disponible."}, status=410)
        delivery.wipe(retrieved_at=timezone.now())
    log_action(
        AuditAction.PGP_KEY_DELIVERY_RETRIEVED,
        actor=request.user,
        obj=delivery,
        request=request,
        fingerprint=delivery.fingerprint,
    )
    notify(
        delivery.created_by,
        NotificationKind.ACCOUNT,
        title="Clé PGP nationale récupérée",
        body=f"{request.user} a récupéré la clé privée nationale que vous lui avez remise.",
        url=reverse("core:pgp_key_manage"),
        send_email=False,
    )
    return JsonResponse({"retrieved": True})


def pgp_key(request):
    """Telechargement de la cle publique nationale."""
    key = pgp.national_public_key()
    if not key:
        return HttpResponse(
            "Aucune clé publique nationale n'est publiée.",
            status=404,
            content_type="text/plain; charset=utf-8",
        )
    response = HttpResponse(key + "\n", content_type="application/pgp-keys")
    response["Content-Disposition"] = 'attachment; filename="evdp-national.asc"'
    return response


def security_txt(request):
    """RFC 9116 : point de contact securite machine-lisible."""
    contact = settings.EVDP["CONTACT_EMAIL"]
    base = request.build_absolute_uri("/")[:-1]
    lines = [
        f"Contact: mailto:{contact}",
        f"Contact: {base}/report/",
        f"Policy: {base}/disclosure-policy/",
        f"Encryption: {base}/pgp-key.asc",
        "Preferred-Languages: fr, en",
        f"Canonical: {base}/.well-known/security.txt",
    ]
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; charset=utf-8")


def _public_statistics():
    """Compteurs publics agreges : jamais d'information identifiante."""
    from apps.coordination.models import Case
    from apps.disclosures.models import Advisory
    from apps.programs.models import Program
    from apps.researchers.models import ResearcherProfile

    return {
        "cases": Case.objects.count(),
        "advisories": Advisory.objects.published().count(),
        "programs": Program.objects.public().count(),
        "researchers": ResearcherProfile.objects.count(),
    }


# ---------------------------------------------------------------------------
# Observabilite
# ---------------------------------------------------------------------------
@never_cache
def health(request):
    """Liveness : le processus repond."""
    return JsonResponse({"status": "ok", "service": "evdp-web"})


@never_cache
def ready(request):
    """Readiness : base de donnees et cache disponibles."""
    checks = {}
    status = 200
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        checks["database"] = "ok"
    except Exception as exc:  # pragma: no cover - depend de l'infrastructure
        checks["database"] = f"error: {exc.__class__.__name__}"
        status = 503
    try:
        cache.set("evdp:ready", "1", timeout=5)
        checks["cache"] = "ok" if cache.get("evdp:ready") == "1" else "degraded"
    except Exception as exc:  # pragma: no cover
        checks["cache"] = f"error: {exc.__class__.__name__}"
        status = 503
    return JsonResponse(
        {"status": "ok" if status == 200 else "unavailable", **checks}, status=status
    )


@never_cache
def metrics(request):
    """Metriques au format texte Prometheus (exposition interne uniquement)."""
    from apps.coordination.models import Case, CaseStatus
    from apps.disclosures.models import Advisory

    lines = [
        "# HELP evdp_cases_total Nombre total de cases enregistrés.",
        "# TYPE evdp_cases_total gauge",
        f"evdp_cases_total {Case.objects.count()}",
        "# HELP evdp_cases_open Nombre de cases non clos.",
        "# TYPE evdp_cases_open gauge",
        f"evdp_cases_open {Case.objects.exclude(status=CaseStatus.CLOSED).count()}",
        "# HELP evdp_cases_sla_breached Cases en dépassement de SLA.",
        "# TYPE evdp_cases_sla_breached gauge",
        f"evdp_cases_sla_breached {Case.objects.sla_breached().count()}",
        "# HELP evdp_advisories_published Advisories publiés.",
        "# TYPE evdp_advisories_published gauge",
        f"evdp_advisories_published {Advisory.objects.published().count()}",
    ]
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


def error_400(request, exception=None):
    return render(request, "errors/400.html", status=400)


def error_403(request, exception=None):
    return render(request, "errors/403.html", status=403)


def csrf_failure(request, reason=""):
    """Echec CSRF : page d'erreur du projet plutot que la page brute de Django."""
    return render(request, "errors/403_csrf.html", status=403)


def error_404(request, exception=None):
    return render(request, "errors/404.html", status=404)


def error_500(request):
    return render(request, "errors/500.html", status=500)


def error_preview(request, code):
    """Apercu des pages d'erreur, en developpement seulement (voir config/urls.py).

    Avec DEBUG=True, Django remplace les pages 404 et 500 par ses pages
    techniques : cette route permet de voir celles du projet telles qu'un
    visiteur les verra en production.
    """
    if code not in (400, 403, 404, 500):
        raise Http404("Code non prévu.")
    return render(request, f"errors/{code}.html", status=code)


DEFAULT_DISCLOSURE_POLICY = """
## Objectif

eVDP offre un canal officiel, sécurisé et juridiquement encadré permettant de
signaler une vulnérabilité affectant un service public ou une infrastructure
numérique nationale.

## Comportement attendu

- Signaler la vulnérabilité dès sa découverte, sans délai injustifié.
- Limiter strictement les tests au nécessaire pour démontrer l'existence de la faille.
- Ne jamais dégrader, altérer ou interrompre un service.
- Ne jamais exfiltrer, conserver ou diffuser des données à caractère personnel.
- Conserver la confidentialité du signalement jusqu'à la divulgation coordonnée.

## Règles de test

Sont autorisés : la reconnaissance passive, les tests non destructifs sur les
périmètres explicitement déclarés dans un programme actif.

Sont interdits : l'ingénierie sociale, le hameçonnage, le déni de service,
les attaques physiques, le spam, la compromission de comptes tiers et toute
exploitation dépassant la preuve de concept.

## Safe Harbor

Une recherche conduite de bonne foi, conforme à la présente politique et au
périmètre du programme concerné, est considérée comme autorisée. eVDP
s'engage à ne pas engager de poursuites à l'encontre d'un chercheur respectant
ces conditions et à l'accompagner en cas de sollicitation d'un tiers.

Cette autorisation ne vaut que dans ces conditions : hors périmètre ou hors
règles, l'accès et le maintien frauduleux dans un système d'information
relèvent du Code pénal (loi n°025-2018/AN, Livre VII).

## Confidentialité

Les rapports sont privés par défaut. Aucun rapport n'est publié
automatiquement. Seule une version assainie (advisory) peut être publiée après
coordination avec l'organisation affectée.

Les données personnelles d'un déclarant (identité, coordonnées) sont traitées
conformément à la loi n°001-2021/AN portant protection des personnes à l'égard
du traitement des données à caractère personnel, sous le contrôle de la
Commission de l'Informatique et des Libertés (CIL).

## Délais

- Accusé de réception : 72 heures.
- Premier triage : 5 jours ouvrés.
- Réponse de l'organisation : 7 jours.
- Divulgation coordonnée par défaut : 90 jours après validation.

## Crédit au chercheur

Le chercheur choisit d'apparaître sous son identité réelle, sous pseudonyme ou
de rester anonyme. Ce choix est respecté dans toute publication.

## Cadre légal applicable (Burkina Faso)

- **Loi n°014-2024/ALT** du 9 juillet 2024 portant sécurité des systèmes
  d'information au Burkina Faso, qui fixe le cadre national de la
  cybersécurité et le rôle de l'ANSSI.
- **Loi n°025-2018/AN** du 31 mai 2018 portant Code pénal, Livre VII :
  infractions relatives aux systèmes d'information.
- **Loi n°001-2021/AN** du 30 mars 2021 portant protection des personnes à
  l'égard du traitement des données à caractère personnel (CIL).
- **Loi n°045-2009/AN** du 10 novembre 2009 portant réglementation des
  services et des transactions électroniques : valeur juridique d'un
  signalement, d'un accusé de réception ou d'une notification électronique.
- **Décret n°2013-1053** portant création de l'ANSSI, dont relève l'équipe
  nationale de réponse aux incidents (CIRT-BF).

## Références normatives

- **ISO/IEC 29147:2018** (divulgation de vulnérabilités) : réception des
  rapports, politique de divulgation et publication d'un avis — étapes
  « Soumis », « Réception accusée » et « Advisory en relecture » jusqu'à la
  clôture.
- **ISO/IEC 30111:2019** (traitement des vulnérabilités) : vérification,
  priorisation et correction — étapes « En analyse » à « Correctif vérifié ».
"""
