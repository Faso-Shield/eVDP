"""Menu lateral : chaque role ne voit que ce qu'il peut ouvrir.

Un menu qui annonce des pages interdites apprend au lecteur a se mefier de ce
qu'il lit. Ces tests fixent le menu role par role, et verifient qu'aucune
entree ne mene a un refus.
"""

import pytest
from django.urls import reverse

from apps.accounts.roles import Role
from apps.core.navigation import sidebar_sections

from .conftest import make_user

pytestmark = pytest.mark.django_db


def menu(user):
    """Menu aplati en (titre de section, libelle), dans l'ordre affiche."""
    return [
        (titre, lien["label"]) for titre, liens in sidebar_sections(user) for lien in liens
    ]


def libelles(user):
    return [libelle for _, libelle in menu(user)]


# ------------------------------------------------------------- comptes signaleurs
#: Le menu attendu pour un compte signaleur, tel que specifie.
MENU_SIGNALEUR = [
    ("Espace", "Tableau de bord"),
    ("Espace", "Espace chercheur"),
    ("Bug Bounty", "Récompenses"),
    ("Publication", "Advisories publiés"),
    (None, "Mon profil"),
]


@pytest.mark.parametrize(
    "role", [Role.SECURITY_RESEARCHER, Role.BUG_BOUNTY_RESEARCHER, Role.PUBLIC_USER]
)
def test_a_reporter_sees_exactly_the_specified_menu(role):
    """Les trois roles signaleurs partagent le meme menu, au mot pres.

    `is_researcher` les couvre tous les trois, PUBLIC_USER compris : l'espace
    chercheur leur est ouvert de la meme facon.
    """
    signaleur = make_user(f"menu-{role.lower()}@test.bf", role=role)
    assert menu(signaleur) == MENU_SIGNALEUR


def test_a_reporter_sees_no_staff_entry(researcher_a):
    """Les quatre rubriques qui fuyaient : coordination, redaction, audit."""
    interdits = {
        "Dossiers",
        "Kanban",
        "Recherche globale",
        "Mes programmes",
        "Rédaction d'advisories",
        "Organisations",
        "Journal d'audit",
        "Administration Django",
    }
    assert not interdits & set(libelles(researcher_a))


def test_no_empty_section_is_announced(researcher_a):
    """Une rubrique vide signalerait un droit manquant, pas un droit absent."""
    assert all(liens for _, liens in sidebar_sections(researcher_a))
    assert "Coordination" not in {titre for titre, _ in sidebar_sections(researcher_a)}
    assert "Administration" not in {titre for titre, _ in sidebar_sections(researcher_a)}


def test_the_profile_link_stands_outside_any_section(researcher_a):
    """Il etait la seule entree que tous trouvaient sous « Administration »."""
    assert menu(researcher_a)[-1] == (None, "Mon profil")


# ----------------------------------------------------------------- autres roles
def test_an_analyst_keeps_coordination_and_drafting(analyst):
    presents = set(libelles(analyst))
    assert {"Dossiers", "Kanban", "Rédaction d'advisories", "Vue CSIRT"} <= presents
    assert "Journal d'audit" not in presents, "l'analyste n'a pas VIEW_AUDIT_LOG"
    assert "Espace chercheur" not in presents


def test_an_auditor_sees_the_log_but_not_the_drafting(auditor):
    presents = set(libelles(auditor))
    assert "Journal d'audit" in presents
    assert "Rédaction d'advisories" not in presents


def test_an_organization_user_sees_its_own_views(dsi_alpha):
    presents = set(libelles(dsi_alpha))
    assert {"Vue organisation", "Dossiers", "Organisations", "Mes programmes"} <= presents


def test_a_superuser_sees_everything_including_django_admin(db):
    from apps.accounts.models import User

    admin = User.objects.create_superuser("menu-admin@test.bf", "MotDePasse!Long12")
    assert "Administration Django" in libelles(admin)


def test_an_anonymous_visitor_gets_no_menu():
    from django.contrib.auth.models import AnonymousUser

    assert sidebar_sections(AnonymousUser()) == []
    assert sidebar_sections(None) == []


# ------------------------------------------------------- aucune entree en impasse
@pytest.mark.parametrize(
    "fixture",
    ["researcher_a", "analyst", "auditor", "dsi_alpha", "coordinator", "triager"],
)
def test_no_menu_entry_leads_to_a_refusal(request, client_for, fixture):
    """Le menu et les vues doivent gater sur la meme capacite.

    C'est la raison d'etre du module : si une vue se protege d'un droit que
    le menu ne verifie pas, le lien mene a un 403 ou a une redirection.
    """
    utilisateur = request.getfixturevalue(fixture)
    client = client_for(utilisateur)

    for _, liens in sidebar_sections(utilisateur):
        for lien in liens:
            if lien["url"].startswith("/admin/"):
                continue  # Servi par Django, deja couvert par is_staff.
            reponse = client.get(lien["url"], follow=True)
            assert reponse.status_code == 200, (
                f"{utilisateur.role} : {lien['label']} ({lien['url']}) "
                f"repond {reponse.status_code}"
            )


def test_the_dashboard_page_renders_the_computed_menu(client_for, researcher_a):
    """Le gabarit lit bien la structure, et non une liste en dur."""
    page = client_for(researcher_a).get(reverse("dashboard:researcher")).content.decode()

    assert "Espace chercheur" in page
    assert "Journal d&#x27;audit" not in page and "Journal d'audit" not in page
    assert "Kanban" not in page
