"""Pages d'erreur du projet (400, 403, 404, 500)."""

import pytest
from django.test import override_settings
from django.urls import reverse

from apps.core.views import error_preview

pytestmark = pytest.mark.django_db


def test_404_page_is_the_project_page(client):
    response = client.get("/page-qui-n-existe-pas/")
    content = response.content.decode()
    assert response.status_code == 404
    assert "Cette page est introuvable" in content
    assert "Retour à l'accueil" in content
    assert "/page-qui-n-existe-pas/" in content  # adresse demandee rappelee


def test_404_for_a_connected_account_leads_to_the_dashboard(client_for, analyst):
    content = client_for(analyst).get("/cases/EVDP-0000-999999/").content.decode()
    assert "Mon tableau de bord" in content
    assert "ne confirme jamais l'existence" in content


def test_404_hides_the_report_link_from_business_accounts(client_for, analyst, researcher_a):
    submit_url = reverse("reports:submit")
    business = client_for(analyst).get("/introuvable/").content.decode()
    researcher = client_for(researcher_a).get("/introuvable/").content.decode()
    assert f'href="{submit_url}"' not in business.split("error-links")[1]
    assert f'href="{submit_url}"' in researcher.split("error-links")[1]


def test_404_escapes_the_requested_path(client):
    content = client.get("/<script>alert(1)</script>/").content.decode()
    assert "<script>alert(1)</script>" not in content


@pytest.mark.parametrize(
    ("code", "heading"),
    [
        (400, "Cette demande n'a pas pu être comprise"),
        (403, "Accès réservé"),
        (404, "Cette page est introuvable"),
        (500, "Un incident est survenu de notre côté"),
    ],
)
def test_each_error_page_renders(rf, code, heading):
    from django.contrib.auth.models import AnonymousUser

    request = rf.get("/")
    request.user = AnonymousUser()
    response = error_preview(request, code)
    assert response.status_code == code
    assert heading in response.content.decode().replace("&#x27;", "'")


@override_settings(DEBUG=False)
def test_preview_route_absent_in_production(client):
    assert client.get("/__erreurs/404/").status_code == 404
    assert "Cette page est introuvable" in client.get("/__erreurs/404/").content.decode()
