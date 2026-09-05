"""Import CSAF 2.0 (Common Security Advisory Framework).

Portee du MVP : lecture d'un document CSAF de categorie `csaf_vex` ou
`csaf_security_advisory` et creation d'un rapport interne par vulnerabilite
declaree. La validation est stricte : tout document non conforme est rejete
sans creation partielle.

TODO : export CSAF des advisories publies, prise en charge des `product_tree`
complexes et des relations produit.
"""

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.reports.models import VulnerabilityReport
from apps.reports.services import submit_report
from apps.vulnerabilities.constants import ReportSource, Severity, VulnerabilityType
from apps.vulnerabilities.cvss import CVSSError, evaluate
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
        raise ValidationError("Le document CSAF doit etre un objet JSON.")

    csaf_document = _require(document, "document", "$")
    if not isinstance(csaf_document, dict):
        raise ValidationError("$.document doit etre un objet.")

    version = csaf_document.get("csaf_version")
    if version != "2.0":
        raise ValidationError(f"Version CSAF non prise en charge : {version!r} (2.0 attendu).")

    category = csaf_document.get("category", "")
    if category not in SUPPORTED_CATEGORIES:
        raise ValidationError(f"Categorie CSAF non prise en charge : {category!r}.")

    _require(csaf_document, "title", "$.document")
    tracking = _require(csaf_document, "tracking", "$.document")
    _require(tracking, "id", "$.document.tracking")

    vulnerabilities = document.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValidationError("Le document ne declare aucune vulnerabilite.")
    if len(vulnerabilities) > MAX_VULNERABILITIES:
        raise ValidationError(
            f"Trop de vulnerabilites dans un seul document (max {MAX_VULNERABILITIES})."
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
        return vector, value, severity
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
