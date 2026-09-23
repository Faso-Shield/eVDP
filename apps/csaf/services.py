"""Echange CSAF 2.0 (Common Security Advisory Framework).

Deux sens de circulation :

  * import  : lecture d'un document de categorie `csaf_vex` ou
    `csaf_security_advisory` et creation d'un rapport interne par
    vulnerabilite declaree. La validation est stricte : tout document non
    conforme est rejete sans creation partielle.
  * export  : representation d'un advisory PUBLIE en document CSAF 2.0.
    L'export ne lit que l'advisory - jamais le case prive (principe 5).

TODO : prise en charge des `product_tree` complexes et des relations produit
a l'import.
"""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.disclosures.models import AdvisoryStatus
from apps.reports.models import VulnerabilityReport
from apps.reports.services import submit_report
from apps.vulnerabilities.constants import ReportSource, Severity, VulnerabilityType
from apps.vulnerabilities.cvss import CVSSError, evaluate, score_as_decimal
from apps.vulnerabilities.models import CVE, CWE

SUPPORTED_CATEGORIES = {
    "csaf_security_advisory",
    "csaf_vex",
    "csaf_base",
    "csaf_informational_advisory",
}
MAX_VULNERABILITIES = 50


def _require(mapping, key, path):
    if key not in mapping:
        raise ValidationError(f"Champ CSAF obligatoire manquant : {path}.{key}")
    return mapping[key]


def validate_document(document):
    """Verifie la structure minimale d'un document CSAF 2.0."""
    if not isinstance(document, dict):
        raise ValidationError("Le document CSAF doit être un objet JSON.")

    csaf_document = _require(document, "document", "$")
    if not isinstance(csaf_document, dict):
        raise ValidationError("$.document doit être un objet.")

    version = csaf_document.get("csaf_version")
    if version != "2.0":
        raise ValidationError(f"Version CSAF non prise en charge : {version!r} (2.0 attendu).")

    category = csaf_document.get("category", "")
    if category not in SUPPORTED_CATEGORIES:
        raise ValidationError(f"Catégorie CSAF non prise en charge : {category!r}.")

    _require(csaf_document, "title", "$.document")
    tracking = _require(csaf_document, "tracking", "$.document")
    _require(tracking, "id", "$.document.tracking")

    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValidationError("Le document ne déclare aucune vulnérabilité.")
    if len(vulnerabilities) > MAX_VULNERABILITIES:
        raise ValidationError(
            f"Trop de vulnérabilités dans un seul document (max {MAX_VULNERABILITIES})."
        )
    return document


def _extract_cvss(vulnerability):
    """Retourne (vecteur, score, severite) a partir des scores CSAF."""
    for score in vulnerability.get("scores", []) or []:
        cvss = score.get("cvss_v3") or score.get("cvss_v4") or {}
        vector = cvss.get("vectorString", "")
        if not vector:
            continue
        try:
            value, severity = evaluate(vector)
        except CVSSError:
            continue
        return vector, score_as_decimal(value), severity
    return "", None, Severity.MEDIUM


def _extract_description(vulnerability, document_title):
    parts = []
    for note in vulnerability.get("notes", []) or []:
        text = (note.get("text") or "").strip()
        if text:
            title = note.get("title") or note.get("category") or "Note"
            parts.append(f"### {title}\n\n{text}")
    if not parts:
        parts.append(document_title)
    return "\n\n".join(parts)[:20000]


def _resolve_cwe(vulnerability):
    cwe_data = vulnerability.get("cwe") or {}
    code = (cwe_data.get("id") or "").upper().strip()
    if not code.startswith("CWE-"):
        return None
    cwe, _ = CWE.objects.get_or_create(
        code=code, defaults={"name": cwe_data.get("name", code)[:255]}
    )
    return cwe


def _resolve_cve(vulnerability):
    cve_id = (vulnerability.get("cve") or "").upper().strip()
    if not cve_id.startswith("CVE-"):
        return None
    cve, _ = CVE.objects.get_or_create(cve_id=cve_id)
    return cve


@transaction.atomic
def import_csaf(document, actor, organization=None, program=None, request=None):
    """Cree un rapport + un case par vulnerabilite declaree dans le document."""
    validate_document(document)
    meta = document["document"]
    title_prefix = meta.get("title", "Import CSAF")[:150]

    created_cases = []
    for vulnerability in document["vulnerabilities"]:
        vector, score, severity = _extract_cvss(vulnerability)
        cve = _resolve_cve(vulnerability)
        title = vulnerability.get("title") or (cve.cve_id if cve else title_prefix)

        report = VulnerabilityReport(
            title=f"{title}"[:200],
            product=", ".join(
                (vulnerability.get("product_status", {}).get("known_affected") or [])[:3]
            )[:200],
            affected_organization=organization,
            program=program,
            vulnerability_type=VulnerabilityType.OTHER,
            cwe=_resolve_cwe(vulnerability),
            cvss_vector=vector,
            cvss_score=score,
            reported_severity=severity,
            description=_extract_description(vulnerability, title_prefix),
            external_reference=((vulnerability.get("references") or [{}])[0].get("url", ""))[
                :500
            ],
            reporter=actor if getattr(actor, "is_authenticated", False) else None,
            accepted_policy=True,
            wants_credit=False,
        )
        case = submit_report(report, request=request, source=ReportSource.CSAF, reporter=actor)
        if cve is not None:
            case.cve = cve
            case.save(update_fields=["cve", "updated_at"])
        created_cases.append(case)

    return created_cases


# ---------------------------------------------------------------------------
# Export CSAF 2.0
# ---------------------------------------------------------------------------
EXPORT_CATEGORY = "csaf_security_advisory"

#: Identifiants produit du `product_tree` genere (un produit affecte, un corrige).
PRODUCT_ID_AFFECTED = "CSAFPID-0001"
PRODUCT_ID_FIXED = "CSAFPID-0002"

#: Severite eVDP -> `baseSeverity` CVSS v3.1. INFO n'existe pas dans la
#: specification CVSS : il est exporte en NONE.
CVSS_BASE_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "NONE",
}


def _absolute_url(path):
    """URL publique de l'instance.

    Meme regle que les liens envoyes par email (apps.notifications.services) :
    SITE_BASE_URL fait foi, ALLOWED_HOSTS sert de repli.
    """
    base = (getattr(settings, "SITE_BASE_URL", "") or "").rstrip("/")
    if not base:
        hosts = [host for host in settings.ALLOWED_HOSTS if host != "*"]
        scheme = "http" if settings.DEBUG else "https"
        base = f"{scheme}://{hosts[0] if hosts else 'localhost'}"
    return f"{base}{path}"


def _iso(value):
    """Horodatage ISO 8601 localise, ou None."""
    return timezone.localtime(value).isoformat() if value else None


def _export_notes(advisory):
    """Notes CSAF construites depuis les seuls champs redactionnels publics."""
    notes = []
    for category, title, text in (
        ("summary", "Resume public", advisory.summary),
        ("description", "Description", advisory.description),
        ("details", "Impact", advisory.impact),
    ):
        if (text or "").strip():
            notes.append({"category": category, "title": title, "text": text.strip()})

    timeline = [
        f"{entry.happened_on:%Y-%m-%d} : {entry.label}" for entry in advisory.timeline.all()
    ]
    if timeline:
        notes.append(
            {
                "category": "general",
                "title": "Chronologie publique",
                "text": "\n".join(timeline),
            }
        )
    return notes


def _export_references(advisory):
    references = [
        {
            "category": "self",
            "summary": f"Advisory {advisory.advisory_id} sur {settings.EVDP['PLATFORM_NAME']}",
            "url": _absolute_url(advisory.get_absolute_url()),
        }
    ]
    references += [
        {"category": "external", "summary": reference.title, "url": reference.url}
        for reference in advisory.external_references.all()
    ]
    return references


def _export_product_tree(advisory):
    """Arbre produit minimal : la cible affectee, et sa version corrigee."""
    affected = " ".join(
        part
        for part in (
            advisory.product
            or (advisory.organization.name if advisory.organization_id else advisory.title),
            advisory.affected_versions,
        )
        if part
    )
    products = [{"product_id": PRODUCT_ID_AFFECTED, "name": affected[:255]}]
    if advisory.fixed_versions.strip():
        fixed = " ".join(part for part in (advisory.product, advisory.fixed_versions) if part)
        products.append({"product_id": PRODUCT_ID_FIXED, "name": fixed[:255]})
    return {"full_product_names": products}


def _export_scores(advisory):
    """Score CVSS v3.x, rattache au produit affecte (`products` est requis)."""
    if not advisory.cvss_vector or advisory.cvss_score is None:
        return []
    version = "3.0" if advisory.cvss_vector.upper().startswith("CVSS:3.0") else "3.1"
    return [
        {
            "cvss_v3": {
                "version": version,
                "vectorString": advisory.cvss_vector,
                "baseScore": float(advisory.cvss_score),
                "baseSeverity": CVSS_BASE_SEVERITY.get(advisory.severity, "NONE"),
            },
            "products": [PRODUCT_ID_AFFECTED],
        }
    ]


def _export_remediations(advisory):
    remediations = []
    for category, details in (
        ("vendor_fix", advisory.solution),
        ("workaround", advisory.workaround),
    ):
        if (details or "").strip():
            remediations.append(
                {
                    "category": category,
                    "details": details.strip(),
                    "product_ids": [PRODUCT_ID_AFFECTED],
                }
            )
    return remediations


def export_advisory_to_csaf(advisory):
    """Represente un advisory publie sous forme de document CSAF 2.0.

    Securite : seuls les champs de l'advisory - deja publics - sont lus.
    Aucune donnee du case source (PoC, etapes de reproduction, URL cible,
    messages, pieces jointes) n'est atteignable depuis cette fonction.
    """
    if advisory.status != AdvisoryStatus.PUBLISHED:
        raise ValidationError("Seul un advisory publie peut etre exporte au format CSAF.")
    if not advisory.is_published:
        raise ValidationError("Cet advisory n'est pas encore effectivement publie.")

    released = _iso(advisory.published_at)

    document = {
        "category": EXPORT_CATEGORY,
        "csaf_version": "2.0",
        "title": advisory.title,
        "lang": "fr",
        # Un advisory publie est public par construction.
        "distribution": {"tlp": {"label": "WHITE"}},
        "publisher": {
            "category": "coordinator",
            "name": settings.EVDP["NATIONAL_TEAM"],
            "namespace": _absolute_url("/"),
            "contact_details": settings.EVDP["CONTACT_EMAIL"],
        },
        "tracking": {
            "id": advisory.advisory_id,
            "status": "final",
            "version": "1",
            "initial_release_date": released,
            "current_release_date": _iso(advisory.updated_at) or released,
            "revision_history": [
                {"number": "1", "date": released, "summary": "Publication initiale."}
            ],
            "generator": {"engine": {"name": settings.EVDP["PLATFORM_NAME"]}},
        },
        "references": _export_references(advisory),
    }

    product_status = {"known_affected": [PRODUCT_ID_AFFECTED]}
    if advisory.fixed_versions.strip():
        product_status["fixed"] = [PRODUCT_ID_FIXED]

    vulnerability = {
        "title": advisory.title,
        "release_date": released,
        "notes": _export_notes(advisory),
        "product_status": product_status,
        "references": _export_references(advisory),
    }
    if advisory.cve_id:
        vulnerability["cve"] = advisory.cve_id
    if advisory.cwe_id:
        vulnerability["cwe"] = {"id": advisory.cwe.code, "name": advisory.cwe.name}
    if advisory.credit:
        # `acknowledgments` est le champ CSAF du credit ; il respecte deja le
        # mode d'identite choisi par le chercheur (voir disclosures.credit_for).
        vulnerability["acknowledgments"] = [{"names": [advisory.credit]}]

    scores = _export_scores(advisory)
    if scores:
        vulnerability["scores"] = scores
    remediations = _export_remediations(advisory)
    if remediations:
        vulnerability["remediations"] = remediations

    return {
        "document": document,
        "product_tree": _export_product_tree(advisory),
        "vulnerabilities": [vulnerability],
    }
