"""Tests des programmes : annuaire public (recherche, filtres, tri) et
gestion (creation, edition, coherence de la politique de recompense)."""

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
    from tests.conftest import build_report

    from .conftest import submit

    make_program(organization, "Programme calme")
    busy = make_program(organization, "Programme actif")
    submit(build_report(researcher_a, organization, busy), reporter=researcher_a)
    submit(build_report(researcher_a, organization, busy), reporter=researcher_a)

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


def manage_payload(program, **overrides):
    payload = {
        "name": program.name,
        "program_type": program.program_type,
        "organization": program.organization_id,
        "status": program.status,
        "confidentiality": program.confidentiality,
        "summary": program.summary,
        "description": program.description,
        "rules": program.rules,
        "out_of_scope_notes": program.out_of_scope_notes,
        "safe_harbor": program.safe_harbor,
        "disclosure_policy": program.disclosure_policy,
        "eligibility": program.eligibility,
        "contact_email": program.contact_email,
        "pgp_public_key": program.pgp_public_key,
        "sla_policy": program.sla_policy_id or "",
        "disclosure_delay_days": program.disclosure_delay_days,
        "requires_verified_email": "on" if program.requires_verified_email else "",
        "allows_anonymous_reports": "on" if program.allows_anonymous_reports else "",
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------- coherence RewardPolicy
def test_switching_program_to_bounty_creates_active_reward_policy(
    client_for, coordinator, vdp_program
):
    """Regression : passer un programme de VDP a Bug Bounty ne creait sa
    RewardPolicy qu'au rechargement suivant, jamais dans la meme requete."""
    client = client_for(coordinator)
    response = client.post(
        reverse("programs:manage", args=[vdp_program.slug]),
        manage_payload(
            vdp_program,
            program_type=ProgramType.BUG_BOUNTY,
            allows_anonymous_reports="",
            requires_verified_email="on",
        ),
    )
    assert response.status_code == 302
    vdp_program.refresh_from_db()
    assert vdp_program.program_type == ProgramType.BUG_BOUNTY
    policy = vdp_program.reward_policy
    assert policy.is_active is True


def test_switching_program_away_from_bounty_deactivates_reward_policy(
    client_for, coordinator, bounty_program
):
    """Regression : repasser un programme Bug Bounty en VDP laissait une
    RewardPolicy perimee toujours active (et donc affichable). Les paliers
    existants (TOTAL_FORMS) sont echoes tels quels : seul program_type change."""
    assert bounty_program.reward_policy.is_active is True
    tier_count = bounty_program.reward_policy.tiers.count()
    assert tier_count > 0
    client = client_for(coordinator)
    formset_management = {
        "tiers-TOTAL_FORMS": str(tier_count),
        "tiers-INITIAL_FORMS": str(tier_count),
        "tiers-MIN_NUM_FORMS": "0",
        "tiers-MAX_NUM_FORMS": "1000",
    }
    for i, tier in enumerate(bounty_program.reward_policy.tiers.all()):
        formset_management[f"tiers-{i}-id"] = str(tier.pk)
        formset_management[f"tiers-{i}-severity"] = tier.severity
        formset_management[f"tiers-{i}-min_amount"] = str(tier.min_amount)
        formset_management[f"tiers-{i}-max_amount"] = str(tier.max_amount)
        formset_management[f"tiers-{i}-description"] = tier.description
    response = client.post(
        reverse("programs:manage", args=[bounty_program.slug]),
        {
            **manage_payload(bounty_program, program_type=ProgramType.VDP),
            **formset_management,
        },
    )
    assert response.status_code == 302
    bounty_program.refresh_from_db()
    assert bounty_program.program_type == ProgramType.VDP
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is False
    # L'historique (paliers, montants) n'est pas supprime, seulement masque.
    assert bounty_program.reward_range() is None
    assert bounty_program.reward_policy.tiers.exists()


def test_ensure_reward_policy_consistency_is_idempotent(bounty_program):
    """Appeler la reconciliation plusieurs fois de suite ne doit ni dupliquer
    ni casser la politique existante."""
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.ensure_reward_policy_consistency()
    assert bounty_program.reward_policy.is_active is True

    bounty_program.program_type = ProgramType.VDP
    bounty_program.save(update_fields=["program_type"])
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is False

    bounty_program.program_type = ProgramType.BUG_BOUNTY
    bounty_program.save(update_fields=["program_type"])
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is True


def test_reward_policy_cannot_attach_to_vdp_program(vdp_program):
    from django.core.exceptions import ValidationError

    from apps.programs.models import RewardPolicy

    policy = RewardPolicy(program=vdp_program)
    with pytest.raises(ValidationError):
        policy.full_clean()


# -------------------------------------------------------------------- creation
def test_program_create_view_reachable(client_for, coordinator):
    client = client_for(coordinator)
    assert client.get(reverse("programs:create")).status_code == 200


def test_create_bounty_program_gets_reward_policy_immediately(
    client_for, coordinator, organization, sla_policy
):
    client = client_for(coordinator)
    response = client.post(
        reverse("programs:create"),
        {
            "name": "Nouveau programme Bounty",
            "program_type": ProgramType.BUG_BOUNTY,
            "organization": organization.pk,
            "status": "DRAFT",
            "confidentiality": "PUBLIC",
            "disclosure_delay_days": 90,
            "sla_policy": sla_policy.pk,
            # Invariant Bug Bounty : pas de recompense sans chercheur identifie
            # et verifie (voir Program.clean).
            "requires_verified_email": "on",
        },
    )
    assert response.status_code == 302
    program = Program.objects.get(name="Nouveau programme Bounty")
    assert program.reward_policy is not None
    assert program.reward_policy.is_active is True
    # Un palier par severite est pre-cree pour eviter d'avoir a les ajouter
    # un par un avant de pouvoir simplement saisir les montants.
    assert program.reward_policy.tiers.count() == 5


def test_unfilled_default_tiers_are_not_shown_as_a_public_reward(
    client, coordinator, organization, sla_policy
):
    """Regression : les paliers 0/0 pre-crees a la creation ne doivent pas
    s'afficher comme si le programme offrait explicitement une recompense
    nulle, ni sur la fiche publique, ni via reward_range()."""
    program = Program.objects.create(
        name="Bounty tout neuf",
        program_type=ProgramType.BUG_BOUNTY,
        organization=organization,
        status="ACTIVE",
        confidentiality="PUBLIC",
        sla_policy=sla_policy,
    )
    program.ensure_reward_policy_consistency()
    assert program.reward_range() is None

    response = client.get(reverse("programs:detail", args=[program.slug]))
    assert response.status_code == 200
    assert "0 – 0" not in response.content.decode()


# ----------------------------------------------- statistiques et hall of fame
def test_program_detail_shows_trust_stats(client, bounty_case):
    """`bounty_case` a franchi l'accuse de reception (workflow v2)."""
    assert bounty_case.acknowledged_at is not None

    response = client.get(reverse("programs:detail", args=[bounty_case.program.slug]))
    assert response.status_code == 200
    assert response.context["stats"]["total_reports"] == 1


def test_program_detail_hall_of_fame_lists_credited_researchers_only(client, bounty_case):
    """Seuls les chercheurs ayant choisi d'etre credites publiquement (et
    jamais "Chercheur anonyme") apparaissent sur la fiche du programme.

    L'advisory est publie par le chemin du workflow v2 (etapes 9 et 10).
    """
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance

    advance(bounty_case, CaseStatus.CLOSED)

    response = client.get(reverse("programs:detail", args=[bounty_case.program.slug]))
    assert "bb-hunter" in response.context["hall_of_fame"]
    assert "Chercheur anonyme" not in response.context["hall_of_fame"]
    assert "bb-hunter" in response.content.decode()
