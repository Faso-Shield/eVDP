"""Deux listes de comptes dans l'administration, et non une.

Comptes metiers et comptes signaleurs sont deux populations : ces tests
fixent la partition, l'etancheite des listes et ce que chacune montre.
"""

import re

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


# ------------------------------------------------------------------- libelles
def libelles(admin_class, modele):
    """Intitules de colonnes tels que l'administration les rendra."""
    instance = admin_class(modele, site)
    rendus = []
    for nom in instance.list_display:
        attribut = getattr(instance, nom, None)
        if attribut is not None:
            rendus.append(attribut.short_description)
        else:
            rendus.append(modele._meta.get_field(nom).verbose_name)
    return rendus


@pytest.mark.parametrize(
    ("admin_class", "modele"),
    [(BusinessAccountAdmin, BusinessAccount), (ReporterAccountAdmin, ReporterAccount)],
)
def test_no_column_header_falls_back_to_an_english_field_name(admin_class, modele):
    """Sans `verbose_name`, Django titre la colonne avec le nom du champ.

    « Full name », « Is active », « Email verified » apparaissaient ainsi au
    milieu d'une interface francaise. Le test echoue si un champ ajoute a une
    liste arrive sans libelle.
    """
    anglais = [
        intitule
        for intitule in libelles(admin_class, modele)
        if re.fullmatch(r"[a-z][a-z0-9]*(?:[ _][a-z0-9]+)*", str(intitule))
    ]
    assert not anglais, f"colonnes sans libelle francais : {anglais}"


def test_the_lists_carry_the_expected_french_headers():
    metiers = [str(x) for x in libelles(BusinessAccountAdmin, BusinessAccount)]
    signaleurs = [str(x) for x in libelles(ReporterAccountAdmin, ReporterAccount)]

    assert "Nom complet" in metiers
    assert "Compte actif" in metiers
    assert "Second facteur" in metiers
    assert "Adresse vérifiée" in signaleurs
    assert "Inscrit le" in signaleurs, "created_at est renomme par la liste"


# ---------------------------------------------------------- analyste senior
def _champs(fieldsets):
    return {champ for _nom, options in fieldsets for champ in options["fields"]}


def test_senior_analyst_can_be_granted_from_the_business_admin():
    """Sans cette case, l'etape 4 (validation 4 yeux) n'a qu'un seul valideur
    possible, le coordinateur."""
    assert "is_senior_analyst" in _champs(BusinessAccountAdmin.fieldsets)
    assert "is_senior_analyst" in _champs(BusinessAccountAdmin.add_fieldsets)
    assert "is_senior_analyst" in BusinessAccountAdmin.list_filter


def test_senior_analyst_flag_is_reserved_to_csirt_analysts(triager):
    from django.core.exceptions import ValidationError

    triager.is_senior_analyst = True
    with pytest.raises(ValidationError) as erreur:
        triager.clean()
    assert "is_senior_analyst" in erreur.value.message_dict


def test_senior_analyst_created_in_admin_gets_validation_rights(client, django_user_model):
    from django.urls import reverse

    from apps.accounts.roles import Capability

    admin = django_user_model.objects.create_superuser(
        email="root@evdp.test", password="Motdepasse-tres-long-42"
    )
    client.force_login(admin)
    session = client.session
    session["mfa_verified"] = True
    session.save()
    reponse = client.post(
        reverse("admin:accounts_businessaccount_add"),
        {
            "email": "senior@evdp.test",
            "full_name": "Analyste Senior",
            "role": Role.CSIRT_ANALYST,
            "is_senior_analyst": "on",
            "password1": "Motdepasse-tres-long-42",
            "password2": "Motdepasse-tres-long-42",
        },
    )
    assert reponse.status_code == 302, reponse.content.decode()[:2000]
    senior = User.objects.get(email="senior@evdp.test")
    assert senior.is_senior_analyst
    assert senior.has_capability(Capability.VALIDATE_SEVERITY)
