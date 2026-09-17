"""Tests de l'annuaire public des programmes : recherche, filtres, tri."""

from decimal import Decimal

import pytest
from django.urls import reverse

from apps.organizations.models import Organization
from apps.programs.models import (
    ConfidentialityLevel,
    Program,
    ProgramScope,
    ProgramStatus,
    ProgramType,
    RewardPolicy,
    RewardTier,
    ScopeTargetType,
)
from apps.vulnerabilities.constants import Severity

pytestmark = pytest.mark.django_db


@pytest.fixture
def other_org(db):
    return Organization.objects.create(name="Office national de l'électricité", acronym="ONE")


def make_program(org, name, program_type=ProgramType.BUG_BOUNTY, **overrides):
    defaults = {
        "status": ProgramStatus.ACTIVE,
        "confidentiality": ConfidentialityLevel.PUBLIC,
    }
    defaults.update(overrides)
    return Program.objects.create(
        name=name, organization=org, program_type=program_type, **defaults
    )


def add_reward(program, low, high, severity=Severity.HIGH):
    policy = RewardPolicy.objects.create(program=program, currency="XOF")
    RewardTier.objects.create(
        policy=policy, severity=severity, min_amount=Decimal(low), max_amount=Decimal(high)
    )
    return policy


# ------------------------------------------------------------------ recherche
def test_search_matches_program_name(client, organization):
    make_program(organization, "Portail eServices")
    make_program(organization, "Facturation en ligne")
    response = client.get(reverse("programs:list"), {"q": "eServices"})
    content = response.content.decode()
    assert "Portail eServices" in content
    assert "Facturation en ligne" not in content


def test_search_matches_organization_name(client, organization, other_org):
    make_program(organization, "Programme A")
    make_program(other_org, "Programme B")
    response = client.get(reverse("programs:list"), {"q": "électricité"})
    content = response.content.decode()
    assert "Programme B" in content
    assert "Programme A" not in content


def test_search_matches_organization_acronym(client, organization, other_org):
    make_program(organization, "Programme A")
    make_program(other_org, "Programme B")
    response = client.get(reverse("programs:list"), {"q": "ONE"})
    assert "Programme B" in response.content.decode()


def test_search_is_case_insensitive(client, organization):
    make_program(organization, "Portail eServices")
    response = client.get(reverse("programs:list"), {"q": "eservices"})
    assert "Portail eServices" in response.content.decode()


def test_no_results_shows_empty_state(client, organization):
    make_program(organization, "Portail eServices")
    response = client.get(reverse("programs:list"), {"q": "inexistant"})
    assert "Aucun programme public actif" in response.content.decode()


# ---------------------------------------------------------------- perimetre
def test_scope_type_filters_programs_without_deflating_counts(client, organization):
    """Le filtre selectionne le programme ; il ne doit pas fausser le
    compteur de perimetres affiche (regression : jointure dupliquee)."""
    program = make_program(organization, "Portail eServices")
    ProgramScope.objects.create(
        program=program, target_type=ScopeTargetType.DOMAIN, identifier="a.gov.bf"
    )
    ProgramScope.objects.create(
        program=program, target_type=ScopeTargetType.DOMAIN, identifier="b.gov.bf"
    )
    ProgramScope.objects.create(
        program=program, target_type=ScopeTargetType.API, identifier="api.gov.bf"
    )
    other = make_program(organization, "Autre programme")
    ProgramScope.objects.create(
        program=other, target_type=ScopeTargetType.MOBILE_APP, identifier="app-mobile"
    )

    response = client.get(reverse("programs:list"), {"scope_type": ScopeTargetType.DOMAIN})
    content = response.content.decode()
    assert "Portail eServices" in content
    assert "Autre programme" not in content
    assert "3 périmètre" in content  # tous les perimetres, pas seulement DOMAIN


def test_scope_type_excludes_programs_without_a_matching_scope(client, organization):
    program = make_program(organization, "API seule")
    ProgramScope.objects.create(
        program=program, target_type=ScopeTargetType.API, identifier="api.gov.bf"
    )
    response = client.get(reverse("programs:list"), {"scope_type": ScopeTargetType.DOMAIN})
    assert "API seule" not in response.content.decode()


def test_out_of_scope_target_does_not_match_the_filter(client, organization):
    """Un perimetre EXCLU ne doit pas rendre le programme eligible au filtre."""
    program = make_program(organization, "Domaine hors perimetre")
    ProgramScope.objects.create(
        program=program,
        target_type=ScopeTargetType.DOMAIN,
        identifier="hors.gov.bf",
        in_scope=False,
    )
    response = client.get(reverse("programs:list"), {"scope_type": ScopeTargetType.DOMAIN})
    assert "Domaine hors perimetre" not in response.content.decode()


# -------------------------------------------------------------------------- tri
def test_sort_by_name_orders_alphabetically(client, organization):
    make_program(organization, "Zebra")
    make_program(organization, "Alpha")
    response = client.get(reverse("programs:list"), {"sort": "name"})
    content = response.content.decode()
    assert content.index("Alpha") < content.index("Zebra")


def test_sort_by_reward_puts_vdp_programs_last(client, organization):
    """Un VDP (sans recompense) ne doit pas apparaitre avant un Bug Bounty
    lorsqu'on trie par recompense decroissante (piege des NULL en SQL)."""
    make_program(organization, "VDP sans recompense", program_type=ProgramType.VDP)
    bounty = make_program(organization, "Bug Bounty recompense")
    add_reward(bounty, 100000, 900000)

    response = client.get(reverse("programs:list"), {"sort": "reward"})
    content = response.content.decode()
    assert content.index("Bug Bounty recompense") < content.index("VDP sans recompense")


def test_sort_by_reports_orders_by_case_count(client, organization, researcher_a):
    from apps.reports.services import submit_report
    from tests.conftest import build_report

    make_program(organization, "Programme calme")
    busy = make_program(organization, "Programme actif")
    submit_report(build_report(researcher_a, organization, busy), reporter=researcher_a)
    submit_report(build_report(researcher_a, organization, busy), reporter=researcher_a)

    response = client.get(reverse("programs:list"), {"sort": "reports"})
    content = response.content.decode()
    assert content.index("Programme actif") < content.index("Programme calme")


# ------------------------------------------------------------------- combinaison
def test_filters_combine_with_type_tab(client, organization):
    make_program(organization, "VDP A", program_type=ProgramType.VDP)
    bounty = make_program(organization, "Bug Bounty A")
    ProgramScope.objects.create(
        program=bounty, target_type=ScopeTargetType.API, identifier="api.gov.bf"
    )

    response = client.get(
        reverse("programs:list"), {"type": "BUG_BOUNTY", "scope_type": ScopeTargetType.API}
    )
    content = response.content.decode()
    assert "Bug Bounty A" in content
    assert "VDP A" not in content


def test_pagination_preserves_active_filters(client, organization):
    for index in range(13):
        make_program(organization, f"Portail eServices {index}")
    response = client.get(reverse("programs:list"), {"q": "eServices"})
    content = response.content.decode()
    assert "q=eServices" in content  # le lien "Suivant" reporte la recherche


def test_type_tab_preserves_search(client, organization):
    make_program(organization, "Portail eServices")
    response = client.get(reverse("programs:list"), {"q": "eServices"})
    content = response.content.decode()
    assert "q=eServices" in content  # les onglets de type reportent la recherche


# ------------------------------------------------------------------- rendu
def test_page_leaks_no_django_comment_markers(client, organization):
    """Regression : les commentaires Django multi-lignes en syntaxe {# #}
    ne sont pas supportes et s'affichent comme texte brut si on les utilise
    par erreur (il faut {% comment %}...{% endcomment %})."""
    make_program(organization, "Portail eServices")
    content = client.get(reverse("programs:list")).content.decode()
    assert "{#" not in content
    assert "#}" not in content


# --------------------------------------------------------------------- statut
def test_default_view_shows_only_active_programs(client, organization):
    make_program(organization, "Programme actif", status=ProgramStatus.ACTIVE)
    make_program(organization, "Programme suspendu", status=ProgramStatus.PAUSED)
    make_program(organization, "Programme cloture", status=ProgramStatus.CLOSED)

    response = client.get(reverse("programs:list"))
    content = response.content.decode()
    assert "Programme actif" in content
    assert "Programme suspendu" not in content
    assert "Programme cloture" not in content


def test_status_disabled_shows_paused_and_closed(client, organization):
    make_program(organization, "Programme actif", status=ProgramStatus.ACTIVE)
    make_program(organization, "Programme suspendu", status=ProgramStatus.PAUSED)
    make_program(organization, "Programme cloture", status=ProgramStatus.CLOSED)

    response = client.get(reverse("programs:list"), {"status": "DISABLED"})
    content = response.content.decode()
    assert "Programme actif" not in content
    assert "Programme suspendu" in content
    assert "Programme cloture" in content


def test_draft_program_never_shown_regardless_of_status_filter(client, organization):
    """Un brouillon n'a jamais ete rendu public : aucun filtre ne doit
    pouvoir l'exposer, meme "Desactive"."""
    make_program(organization, "Brouillon jamais publie", status=ProgramStatus.DRAFT)

    for status in ("", "ACTIVE", "DISABLED"):
        params = {"status": status} if status else {}
        response = client.get(reverse("programs:list"), params)
        assert "Brouillon jamais publie" not in response.content.decode()


def test_private_disabled_program_stays_hidden(client, organization):
    """Un programme suspendu mais non public reste invisible, statut ou pas."""
    make_program(
        organization,
        "Suspendu prive",
        status=ProgramStatus.PAUSED,
        confidentiality=ConfidentialityLevel.PRIVATE,
    )
    response = client.get(reverse("programs:list"), {"status": "DISABLED"})
    assert "Suspendu prive" not in response.content.decode()


def test_status_combines_with_search(client, organization):
    make_program(organization, "Portail suspendu", status=ProgramStatus.PAUSED)
    make_program(organization, "Autre suspendu", status=ProgramStatus.CLOSED)

    response = client.get(reverse("programs:list"), {"status": "DISABLED", "q": "Portail"})
    content = response.content.decode()
    assert "Portail suspendu" in content
    assert "Autre suspendu" not in content


def test_status_widget_defaults_to_active_even_after_other_filters(client, organization):
    """Piege Django classique : un ChoiceField lie ignore son `initial` des
    qu'une cle differente du querystring est soumise. Sans le filet en vue,
    le select afficherait un statut vide plutot qu'"Actif" apres une
    recherche."""
    make_program(organization, "Programme actif")
    response = client.get(reverse("programs:list"), {"q": "Programme"})
    content = response.content.decode()
    assert '<option value="ACTIVE" selected>' in content
