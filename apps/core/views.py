"""Pages publiques institutionnelles et sondes d'observabilite."""

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache

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
        },
    )


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
