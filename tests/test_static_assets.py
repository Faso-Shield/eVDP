"""Verifie que tous les fichiers statiques references par les gabarits existent.

En production, `CompressedManifestStaticFilesStorage` leve une exception si un
gabarit reference un fichier absent : une simple faute de frappe rend alors
TOUTES les pages HTML indisponibles. Les reglages de test utilisent un stockage
permissif, donc ce test remplace le controle qui manquerait sinon.
"""

import re
from pathlib import Path

import pytest
from django.conf import settings

STATIC_TAG = re.compile(r"""\{%\s*static\s+['"]([^'"]+)['"]""")


def _template_files():
    for directory in settings.TEMPLATES[0]["DIRS"]:
        yield from Path(directory).rglob("*.html")


def _static_roots():
    return [Path(directory) for directory in settings.STATICFILES_DIRS]


def test_every_static_reference_exists():
    missing = []
    roots = _static_roots()

    for template in _template_files():
        content = template.read_text(encoding="utf-8")
        for reference in STATIC_TAG.findall(content):
            if any((root / reference).exists() for root in roots):
                continue
            missing.append(f"{template.name} -> {reference}")

    assert not missing, "Fichiers statiques references mais absents :\n" + "\n".join(
        sorted(missing)
    )


def test_expected_assets_are_present():
    """Garde-fou explicite sur les ressources indispensables au rendu.

    Le logo est distribue en PNG et non en SVG : le master fourni par le
    design est une image matricielle. Voir docs/brand/README.md.
    """
    roots = _static_roots()
    for reference in [
        "css/evdp.css",
        "js/htmx.min.js",
        "img/favicon-32.png",
        "img/favicon-192.png",
        "img/apple-touch-icon.png",
        "img/logo-evdp-tile.png",
    ]:
        assert any(
            (root / reference).exists() for root in roots
        ), f"Ressource manquante : {reference}"


# ---------------------------------------------------------------------------
# Regression : un dossier sans organisation ne doit pas casser les gabarits.
# Un argument de filtre Django (`|default:case.organization.name`) est resolu
# strictement : il leve VariableDoesNotExist quand l'organisation est nulle,
# ce qui provoquait une erreur 500 sur la liste des dossiers et le tableau de
# bord CSIRT. Les gabarits utilisent desormais `{% firstof %}`.
# ---------------------------------------------------------------------------
@pytest.mark.django_db
def test_views_render_with_case_without_organization(
    client_for, analyst, researcher_a, sla_policy
):
    from apps.reports.services import submit_report

    from .conftest import build_report

    submit_report(
        build_report(researcher_a, organization=None, title="Sans organisation"),
        reporter=researcher_a,
    )

    client = client_for(analyst)
    for url in ["/cases/", "/cases/kanban/", "/dashboard/csirt/"]:
        assert client.get(url).status_code == 200, f"500 sur {url}"


@pytest.mark.django_db
def test_advisory_list_renders_without_organization(client, coordinator, case_alpha):
    from apps.disclosures.models import AdvisoryStatus
    from apps.disclosures.services import create_advisory_from_case, publish_advisory

    case_alpha.organization = None
    case_alpha.save(update_fields=["organization"])

    advisory = create_advisory_from_case(case_alpha, coordinator, summary="Resume public.")
    advisory.status = AdvisoryStatus.APPROVED
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    assert client.get("/advisories/").status_code == 200
