"""Cartographie : organisations du Burkina Faso et signalements afferents."""

from decimal import Decimal

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import reverse

from apps.organizations import geo
from apps.organizations.models import Organization, Sector

pytestmark = pytest.mark.django_db

MAP = reverse("dashboard:map")
DATA = reverse("dashboard:map_data")


def _by_name(payload):
    return {org["name"]: org for org in payload["organizations"]}


# ----------------------------------------------------------------- referentiel
@pytest.mark.parametrize(
    "saisie, attendu",
    [
        ("Centre", "Kadiogo"),
        ("kadiogo", "Kadiogo"),
        ("Hauts-Bassins", "Guiriko"),
        ("hauts bassins", "Guiriko"),
        ("Plateau Central", "Oubri"),
        ("Djoro", "Djôrô"),
        ("Bobo-Dioulasso", "Guiriko"),
    ],
)
def test_old_and_new_region_names_resolve_to_the_same_region(saisie, attendu):
    assert geo.find_region(saisie)["name"] == attendu


def test_unknown_region_is_not_placed():
    org = Organization(name="Sans lieu", region="Atlantide")
    assert geo.locate(org) is None


def test_precise_coordinates_win_over_the_region():
    org = Organization(
        name="Precise", region="Centre", latitude=Decimal("11.18"), longitude=Decimal("-4.29")
    )
    assert geo.locate(org) == (11.18, -4.29, True)


def test_region_fallback_is_flagged_as_approximate():
    lat, lon, precise = geo.locate(Organization(name="Approx", region="Sahel"))
    assert (lat, lon) == (14.0354, -0.0345)
    assert precise is False


# ---------------------------------------------------------------------- modele
def test_coordinates_outside_burkina_are_rejected():
    """Une inversion lat/lon place Ouagadougou au large de la Somalie."""
    org = Organization(name="Inverse", latitude=Decimal("-1.52"), longitude=Decimal("12.37"))
    with pytest.raises(ValidationError):
        org.full_clean()


def test_a_lone_coordinate_is_rejected():
    org = Organization(name="Moitie", latitude=Decimal("12.37"))
    with pytest.raises(ValidationError):
        org.full_clean()


# --------------------------------------------------------------------- acces
@pytest.mark.parametrize("fixture", ["analyst", "coordinator", "auditor"])
def test_csirt_and_national_roles_open_the_map(request, client_for, fixture):
    client = client_for(request.getfixturevalue(fixture))
    assert client.get(MAP).status_code == 200
    assert client.get(DATA).status_code == 200


@pytest.mark.parametrize("fixture", ["researcher_a", "dsi_alpha"])
def test_other_roles_are_refused(request, client_for, fixture):
    client = client_for(request.getfixturevalue(fixture))
    assert client.get(MAP).status_code == 403
    assert client.get(DATA).status_code == 403


def test_anonymous_visitor_is_redirected_to_login(client):
    assert client.get(DATA).status_code == 302


# ---------------------------------------------------------------------- donnees
def test_reports_are_counted_on_their_organization(
    client_for, analyst, organization, other_organization, case_alpha, case_beta
):
    organization.region = "Centre"
    organization.save()
    other_organization.latitude, other_organization.longitude = Decimal("11.18"), Decimal(
        "-4.3"
    )
    other_organization.region = "Hauts-Bassins"
    other_organization.save()

    payload = client_for(analyst).get(DATA).json()
    orgs = _by_name(payload)

    alpha = orgs["Ministere Alpha"]
    assert (alpha["lat"], alpha["lon"], alpha["precise"]) == (12.3714, -1.5197, False)
    assert alpha["region"] == "Kadiogo"
    assert alpha["total"] == 1 and alpha["open"] == 1
    assert alpha["recent"][0]["case_id"] == case_alpha.case_id
    assert alpha["cases_url"].endswith(f"?organization={organization.id}")

    beta = orgs["Ministere Beta"]
    assert beta["precise"] is True and beta["region"] == "Guiriko"

    assert payload["totals"]["cases"] == 2
    assert {r["name"] for r in payload["regions"]} == {"Kadiogo", "Guiriko"}


def test_an_organization_that_cannot_be_placed_is_reported_as_missing(
    client_for, analyst, organization, case_alpha
):
    payload = client_for(analyst).get(DATA).json()
    assert "Ministere Alpha" not in _by_name(payload)
    assert payload["totals"]["unlocated"] == 1


def test_filters_narrow_the_map(
    client_for, analyst, organization, other_organization, case_alpha
):
    for org in (organization, other_organization):
        org.region = "Centre"
        org.save()
    client = client_for(analyst)

    assert set(_by_name(client.get(DATA).json())) == {"Ministere Alpha", "Ministere Beta"}
    assert set(_by_name(client.get(DATA, {"reported": "1"}).json())) == {"Ministere Alpha"}
    assert set(_by_name(client.get(DATA, {"sector": Sector.EDUCATION}).json())) == {
        "Ministere Beta"
    }
    assert set(_by_name(client.get(DATA, {"region": "Kadiogo"}).json())) == {
        "Ministere Alpha",
        "Ministere Beta",
    }
    assert not client.get(DATA, {"region": "Liptako"}).json()["organizations"]
    assert set(_by_name(client.get(DATA, {"q": "beta"}).json())) == {"Ministere Beta"}


# ------------------------------------------------------------------------- CSP
def test_tile_origin_is_allowed_by_the_csp():
    assert settings.MAP_TILE_ORIGIN in settings.CSP_DIRECTIVES["img-src"]


@pytest.mark.parametrize(
    "url, origine",
    [
        (
            "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
            "https://*.tile.openstreetmap.org",
        ),
        ("https://tuiles.anssi.bf/{z}/{x}/{y}.png", "https://tuiles.anssi.bf"),
        ("/static/tuiles/{z}/{x}/{y}.png", ""),
        ("", ""),
    ],
)
def test_tile_origin_derivation(url, origine):
    from config.settings.base import _tile_origin

    assert _tile_origin(url) == origine


# ------------------------------------------------------- fiche organisation
def test_manage_page_offers_a_position_picker_and_a_map_link(
    client_for, coordinator, organization
):
    response = client_for(coordinator).get(
        reverse("organizations:manage", args=[organization.slug])
    )
    body = response.content.decode()
    assert 'id="location-picker-map"' in body
    assert f"{MAP}?org={organization.id}" in body


def test_no_map_link_for_those_who_cannot_open_the_map(client_for, dsi_alpha, organization):
    """Le DSI gere sa fiche mais n'a pas acces a la carte nationale."""
    body = (
        client_for(dsi_alpha)
        .get(reverse("organizations:manage", args=[organization.slug]))
        .content.decode()
    )
    assert 'id="location-picker-map"' in body
    assert f"{MAP}?org=" not in body


def test_saved_coordinates_are_the_position_shown_on_the_map(
    client_for, coordinator, organization
):
    organization.region = "Centre"
    organization.save()
    client = client_for(coordinator)
    form = {
        "name": organization.name,
        "acronym": organization.acronym,
        "organization_type": organization.organization_type,
        "sector": organization.sector,
        "region": "Centre",
        "latitude": "12.377635",
        "longitude": "-1.487849",
        "status": organization.status,
        "accepts_vdp": "on",
    }
    response = client.post(reverse("organizations:manage", args=[organization.slug]), form)
    assert response.status_code == 302

    alpha = _by_name(client.get(DATA).json())["Ministere Alpha"]
    assert (alpha["lat"], alpha["lon"], alpha["precise"]) == (12.377635, -1.487849, True)
