"""Tests des profils chercheurs : visibilite selon le mode d'identite, reputation."""

import pytest
from django.urls import reverse

from apps.researchers.models import IdentityMode
from apps.researchers.services import get_or_create_profile

pytestmark = pytest.mark.django_db


def _profile_for(user, **overrides):
    profile = get_or_create_profile(user)
    for key, value in overrides.items():
        setattr(profile, key, value)
    profile.save()
    return profile


# ------------------------------------------------------- visibilite publique
def test_public_identity_mode_shows_real_name(researcher_a):
    profile = _profile_for(researcher_a, identity_mode=IdentityMode.PUBLIC)
    assert profile.public_identity() == (researcher_a.full_name or researcher_a.display_name)


def test_pseudonym_identity_mode_never_shows_real_name(researcher_a):
    profile = _profile_for(
        researcher_a, identity_mode=IdentityMode.PSEUDONYM, pseudonym="alpha-hunter"
    )
    identity = profile.public_identity()
    assert identity == "alpha-hunter"
    assert researcher_a.email not in identity
    assert (researcher_a.full_name or "zzz-no-match") not in identity


def test_private_identity_mode_reveals_nothing(researcher_a):
    profile = _profile_for(
        researcher_a, identity_mode=IdentityMode.PRIVATE, pseudonym="ne-doit-pas-apparaitre"
    )
    identity = profile.public_identity()
    assert identity == "Chercheur anonyme"
    assert "ne-doit-pas-apparaitre" not in identity
    assert researcher_a.email not in identity


def test_private_profile_returns_404_to_strangers(client, researcher_a, researcher_b):
    profile = _profile_for(
        researcher_a, identity_mode=IdentityMode.PRIVATE, is_public_profile=True
    )
    client.force_login(researcher_b)
    response = client.get(reverse("researchers:detail", args=[profile.slug]))
    assert response.status_code == 404


def test_private_profile_is_visible_to_its_owner(client_for, researcher_a):
    profile = _profile_for(researcher_a, identity_mode=IdentityMode.PRIVATE)
    client = client_for(researcher_a)
    response = client.get(reverse("researchers:detail", args=[profile.slug]))
    assert response.status_code == 200


def test_private_profile_is_visible_to_national_roles(client_for, coordinator, researcher_a):
    profile = _profile_for(researcher_a, identity_mode=IdentityMode.PRIVATE)
    client = client_for(coordinator)
    response = client.get(reverse("researchers:detail", args=[profile.slug]))
    assert response.status_code == 200


def test_non_public_profile_excluded_from_directory(client, researcher_a):
    _profile_for(researcher_a, is_public_profile=False, identity_mode=IdentityMode.PSEUDONYM)
    response = client.get(reverse("researchers:list"))
    assert researcher_a.email not in response.content.decode()


def test_private_mode_excluded_from_directory_even_if_flagged_public(client, researcher_a):
    """is_public_profile=True n'a pas d'effet si identity_mode=PRIVATE :
    l'annuaire doit rester une liste blanche stricte."""
    profile = _profile_for(
        researcher_a,
        is_public_profile=True,
        identity_mode=IdentityMode.PRIVATE,
        pseudonym="ne-doit-pas-apparaitre",
    )
    content = client.get(reverse("researchers:list")).content.decode()
    assert "ne-doit-pas-apparaitre" not in content
    assert profile.slug not in content


# ------------------------------------------------------------------ reputation
def test_recompute_counts_only_own_validated_cases(researcher_a, case_alpha):
    from apps.coordination.workflow import CaseStatus

    case_alpha.reporter = researcher_a
    case_alpha.status = CaseStatus.VALIDATED
    case_alpha.save(update_fields=["reporter", "status"])

    profile = get_or_create_profile(researcher_a)
    profile.recompute()
    assert profile.reports_submitted == 1
    assert profile.reports_validated == 1


def test_recompute_is_not_editable_by_the_researcher_via_profile_form(
    client_for, researcher_a
):
    """Les compteurs sont `editable=False` : verifie qu'ils ne figurent pas
    dans le formulaire soumis par le chercheur sur son propre profil."""
    from apps.accounts.forms import ResearcherProfileForm

    assert "reputation" not in ResearcherProfileForm.Meta.fields
    assert "reports_validated" not in ResearcherProfileForm.Meta.fields
