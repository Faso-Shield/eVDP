"""Pages publiques institutionnelles et sondes d'observabilite."""

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import HttpResponse, JsonResponse
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
        "eVDP est la plateforme nationale de divulgation coordonnee de "
        "vulnerabilites et de gestion des programmes Bug Bounty.",
    )
    return render(
        request,
        "core/page.html",
        {"page_title": "A propos", "body": render_markdown(body)},
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
            "Aucune cle publique nationale n'est publiee.",
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
        "# HELP evdp_cases_total Nombre total de cases enregistres.",
        "# TYPE evdp_cases_total gauge",
        f"evdp_cases_total {Case.objects.count()}",
        "# HELP evdp_cases_open Nombre de cases non clos.",
        "# TYPE evdp_cases_open gauge",
        f"evdp_cases_open {Case.objects.exclude(status=CaseStatus.CLOSED).count()}",
        "# HELP evdp_cases_sla_breached Cases en depassement de SLA.",
        "# TYPE evdp_cases_sla_breached gauge",
        f"evdp_cases_sla_breached {Case.objects.sla_breached().count()}",
        "# HELP evdp_advisories_published Advisories publies.",
        "# TYPE evdp_advisories_published gauge",
        f"evdp_advisories_published {Advisory.objects.published().count()}",
    ]
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


def error_400(request, exception=None):
    return render(request, "errors/400.html", status=400)


def error_403(request, exception=None):
    return render(request, "errors/403.html", status=403)


def error_404(request, exception=None):
    return render(request, "errors/404.html", status=404)


def error_500(request):
    return render(request, "errors/500.html", status=500)


DEFAULT_DISCLOSURE_POLICY = """
## Objectif

eVDP offre un canal officiel, securise et juridiquement encadre permettant de
signaler une vulnerabilite affectant un service public ou une infrastructure
numerique nationale.

## Comportement attendu

- Signaler la vulnerabilite des sa decouverte, sans delai injustifie.
- Limiter strictement les tests au necessaire pour demontrer l'existence de la faille.
- Ne jamais degrader, alterer ou interrompre un service.
- Ne jamais exfiltrer, conserver ou diffuser des donnees a caractere personnel.
- Conserver la confidentialite du signalement jusqu'a la divulgation coordonnee.

## Regles de test

Sont autorises : la reconnaissance passive, les tests non destructifs sur les
perimetres explicitement declares dans un programme actif.

Sont interdits : l'ingenierie sociale, le hameconnage, le deni de service,
les attaques physiques, le spam, la compromission de comptes tiers et toute
exploitation depassant la preuve de concept.

## Safe Harbor

Une recherche conduite de bonne foi, conforme a la presente politique et au
perimetre du programme concerne, est consideree comme autorisee. eVDP
s'engage a ne pas engager de poursuites a l'encontre d'un chercheur respectant
ces conditions et a l'accompagner en cas de sollicitation d'un tiers.

Le Code penal (loi n°025-2018/AN, Livre VII) sanctionne l'acces et le
maintien frauduleux dans un systeme d'information. Une recherche menee
dans les conditions decrites ci-dessus, sur le perimetre autorise par un
programme actif, est en dehors du champ de ces infractions.

## Confidentialite

Les rapports sont prives par defaut. Aucun rapport n'est publie
automatiquement. Seule une version assainie (advisory) peut etre publiee apres
coordination avec l'organisation affectee.

Le traitement des donnees personnelles d'un declarant (identite,
coordonnees) est soumis a la loi n°001-2021/AN portant protection des
personnes a l'egard du traitement des donnees a caractere personnel, sous
le controle de la Commission de l'Informatique et des Libertes (CIL).

## Delais

- Accuse de reception : 72 heures.
- Premier triage : 5 jours ouvres.
- Reponse de l'organisation : 7 jours.
- Divulgation coordonnee par defaut : 90 jours apres validation.

## Credit au chercheur

Le chercheur choisit d'apparaitre sous son identite reelle, sous pseudonyme ou
de rester anonyme. Ce choix est respecte dans toute publication.

## Cadre legal applicable (Burkina Faso)

Ce canal ne repose pas sur une simple charte interne : il s'inscrit dans un
ensemble de textes nationaux en vigueur.

- **Loi n°014-2024/ALT** du 9 juillet 2024 portant securite des systemes
  d'information au Burkina Faso, qui renforce le role de l'ANSSI (Agence
  Nationale de Securite des Systemes d'Information) et fixe le cadre
  reglementaire national de la cybersecurite.
- **Loi n°025-2018/AN** du 31 mai 2018 portant Code penal, Livre VII, qui
  qualifie et sanctionne les infractions relatives aux systemes
  d'information. La clause Safe Harbor ci-dessus precise les conditions
  dans lesquelles une recherche de bonne foi reste en dehors du champ de
  ces infractions.
- **Loi n°001-2021/AN** du 30 mars 2021 portant protection des personnes a
  l'egard du traitement des donnees a caractere personnel (elle abroge la
  loi n°010-2004/AN), placee sous le controle de la Commission de
  l'Informatique et des Libertes (CIL, www.cil.bf).
- **Loi n°045-2009/AN** du 10 novembre 2009 portant reglementation des
  services et des transactions electroniques, qui donne sa valeur
  juridique a un signalement, un accuse de reception ou une notification
  transmis par voie electronique.
- **Decret n°2013-1053** portant creation de l'ANSSI, dont depend le
  CIRT-BF (equipe nationale de reponse aux incidents, cirt@cirt.bf),
  interlocuteur technique en cas d'incident avere.

## References normatives

Le processus de traitement d'un signalement suit les deux normes de
reference du domaine :

- **ISO/IEC 29147:2018** (Vulnerability disclosure) encadre la reception
  des rapports, l'etablissement d'une politique de divulgation et la
  publication d'un avis correctif. Les etapes Soumis, Recu, Divulgation
  planifiee et Publie de ce workflow correspondent a ce cycle.
- **ISO/IEC 30111:2019** (Vulnerability handling processes) encadre le
  traitement interne d'un rapport une fois recu : verification,
  priorisation, correction. Les etapes En triage, Valide, Severite
  attribuee et Remediation en cours de ce workflow correspondent a ce
  cycle.

Ces deux normes ne sont pas citees pour la forme : chaque etape qu'elles
decrivent a un statut correspondant dans `apps/coordination/workflow.py`.
"""
