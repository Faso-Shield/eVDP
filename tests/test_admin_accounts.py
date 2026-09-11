"""Deux listes de comptes dans l'administration, et non une.

Comptes metiers et comptes signaleurs sont deux populations : ces tests
fixent la partition, l'etancheite des listes et ce que chacune montre.
"""

import pytest
from django.contrib.admin.sites import site

from apps.accounts.admin import BusinessAccountAdmin, ReporterAccountAdmin
from apps.accounts.models import BusinessAccount, ReporterAccount, User
from apps.accounts.roles import BUSINESS_ROLES, RESEARCHER_ROLES, Role

pytestmark = pytest.mark.django_db


def lignes(admin_class, modele, rf, utilisateur):
    requete = rf.get("/admin/")
    requete.user = utilisateur
    return admin_class(modele, site).get_queryset(requete)


# ------------------------------------------------------------------ partition
def test_every_role_belongs_to_exactly_one_list():
    """Aucun role orphelin, aucun role dans les deux listes."""
    assert set(BUSINESS_ROLES) | set(RESEARCHER_ROLES) == set(Role.values)
    assert not set(BUSINESS_ROLES) & set(RESEARCHER_ROLES)


def test_a_new_role_lands_among_business_accounts_by_default():
    """BUSINESS_ROLES est un complement : le defaut sur est le plus protege.

    Un role ajoute a `Role` sans decision explicite se retrouve soumis au
    second facteur et gere depuis la liste metier, plutot que dispense par
    omission.
    """
    assert BUSINESS_ROLES == frozenset(set(Role.values) - set(RESEARCHER_ROLES))


# -------------------------------------------------------------- etancheite
def test_the_two_lists_never_show_the_same_account(
    rf, coordinator, analyst, auditor, researcher_a, bounty_researcher
):
    metiers = lignes(BusinessAccountAdmin, BusinessAccount, rf, coordinator)
    signaleurs = lignes(ReporterAccountAdmin, ReporterAccount, rf, coordinator)

    assert set(metiers) & set(signaleurs) == set()
    assert {coordinator.pk, analyst.pk, auditor.pk} <= {u.pk for u in metiers}
    assert {researcher_a.pk, bounty_researcher.pk} <= {u.pk for u in signaleurs}


def test_together_the_lists_cover_every_account(
    rf, coordinator, analyst, researcher_a, bounty_researcher, dsi_alpha
):
    """Aucun compte ne doit devenir ingerable en tombant entre les deux."""
    metiers = lignes(BusinessAccountAdmin, BusinessAccount, rf, coordinator)
    signaleurs = lignes(ReporterAccountAdmin, ReporterAccount, rf, coordinator)

    assert {u.pk for u in metiers} | {u.pk for u in signaleurs} == set(
        User.objects.values_list("pk", flat=True)
    )


def test_a_role_change_moves_the_account_between_lists(rf, coordinator, analyst):
    analyst.role = Role.SECURITY_RESEARCHER
    analyst.save(update_fields=["role"])

    metiers = lignes(BusinessAccountAdmin, BusinessAccount, rf, coordinator)
    signaleurs = lignes(ReporterAccountAdmin, ReporterAccount, rf, coordinator)

    assert analyst.pk not in {u.pk for u in metiers}
    assert analyst.pk in {u.pk for u in signaleurs}


# ------------------------------------------------------- colonnes et actions
def test_the_second_factor_column_exists_only_where_it_applies():
    """Une colonne MFA sur les signaleurs afficherait une donnee sans objet."""
    assert "second_facteur" in BusinessAccountAdmin.list_display
    assert "second_facteur" not in ReporterAccountAdmin.list_display
    assert "mfa_enabled" in BusinessAccountAdmin.list_filter
    assert "mfa_enabled" not in ReporterAccountAdmin.list_filter


def test_the_mfa_reset_action_exists_only_on_business_accounts():
    assert "reinitialiser_mfa" in BusinessAccountAdmin.actions
    assert not getattr(ReporterAccountAdmin, "actions", None)


def test_each_list_shows_what_its_population_is_judged_on():
    """Reputation et rapports d'un cote, organisation et acces de l'autre."""
    assert "organisation" in BusinessAccountAdmin.list_display
    assert "reputation" in ReporterAccountAdmin.list_display
    assert "rapports_soumis" in ReporterAccountAdmin.list_display
    assert "reputation" not in BusinessAccountAdmin.list_display


def test_the_reporter_list_reads_the_public_identity(rf, coordinator, researcher_a):
    """La colonne doit rendre ce que le public voit, pas l'email en clair."""
    admin = ReporterAccountAdmin(ReporterAccount, site)
    compte = lignes(ReporterAccountAdmin, ReporterAccount, rf, coordinator).get(
        pk=researcher_a.pk
    )
    assert admin.identite_publique(compte) == researcher_a.public_identity()


def test_the_reporter_list_survives_an_account_without_profile(rf, coordinator, researcher_a):
    """Un compte public peut n'avoir jamais rien soumis."""
    admin = ReporterAccountAdmin(ReporterAccount, site)
    sans_profil = User.objects.create_user(
        email="jamais-soumis@exemple.bf", password="x", role=Role.PUBLIC_USER
    )
    compte = lignes(ReporterAccountAdmin, ReporterAccount, rf, coordinator).get(
        pk=sans_profil.pk
    )

    assert admin.reputation(compte) == "—"
    assert admin.rapports_soumis(compte) == "—"


# ---------------------------------------------------------------- inscription
def test_the_registry_exposes_two_lists_and_hides_the_raw_user_model(rf, coordinator):
    """`User` reste enregistre pour les autocompletions, mais hors index."""
    assert BusinessAccount in site._registry
    assert ReporterAccount in site._registry
    assert User in site._registry

    requete = rf.get("/admin/")
    requete.user = coordinator
    assert site._registry[User].get_model_perms(requete) == {}
