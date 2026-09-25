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
#:
#: « Espace chercheur » n'y figure pas : `dashboard:home` aiguille un
#: signaleur vers cette page precise, donc l'entree doublait « Tableau de
#: bord » a l'octet pres. « Portefeuille » y figure en revanche : c'est une
#: page a part, ouverte aux memes roles que la vue qu'elle mene
#: (require_roles(*RESEARCHER_ROLES)).
MENU_SIGNALEUR = [
    ("Espace", "Tableau de bord"),
    ("Espace", "Portefeuille"),
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
    assert {"Dossiers", "Kanban", "Rédaction d'advisories"} <= presents
    assert "Journal d'audit" not in presents, "l'analyste n'a pas VIEW_AUDIT_LOG"
    assert "Espace chercheur" not in presents
    assert "Vue CSIRT" not in presents, "c'est la ou son tableau de bord mene"


def test_an_auditor_sees_the_log_but_not_the_drafting(auditor):
    presents = set(libelles(auditor))
    assert "Journal d'audit" in presents
    assert "Rédaction d'advisories" not in presents


def test_an_organization_user_sees_its_own_views(dsi_alpha, manager_alpha):
    presents = set(libelles(manager_alpha))
    assert {"Dossiers", "Organisations", "Mes programmes"} <= presents
    assert "Vue organisation" not in presents, "c'est la ou son tableau de bord mene"
    # La DSI ne gere plus la fiche de son organisation.
    assert "Organisations" not in set(libelles(dsi_alpha))


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

    assert "Advisories publi" in page
    assert "Journal d&#x27;audit" not in page and "Journal d'audit" not in page
    assert "Kanban" not in page


# ------------------------------------------------ pas de doublon d'atterrissage
@pytest.mark.parametrize(
    "fixture",
    ["researcher_a", "analyst", "auditor", "dsi_alpha", "coordinator", "triager"],
)
def test_no_entry_duplicates_where_the_dashboard_already_lands(request, client_for, fixture):
    """« Tableau de bord » n'affiche rien : il aiguille. Le menu ne doit pas
    proposer une seconde entree vers la meme page."""
    utilisateur = request.getfixturevalue(fixture)
    arrivee = client_for(utilisateur).get(reverse("dashboard:home")).url

    destinations = [
        lien["url"]
        for _, liens in sidebar_sections(utilisateur)
        for lien in liens
        if lien["url"] != reverse("dashboard:home")
    ]
    assert arrivee not in destinations, f"{utilisateur.role} : {arrivee} liste deux fois"


def test_an_auditor_keeps_the_csirt_view_because_it_is_another_page(client_for, auditor):
    """La regle porte sur l'egalite des destinations, pas sur le role.

    L'auditeur atterrit sur la vue nationale : la vue CSIRT reste une page
    distincte, et son entree garde sa raison d'etre.
    """
    arrivee = client_for(auditor).get(reverse("dashboard:home")).url
    assert arrivee == reverse("dashboard:national")
    assert "Vue CSIRT" in libelles(auditor)


def test_the_router_and_the_menu_read_the_same_rule(client_for, analyst):
    """`landing_route` sert aux deux : elles ne peuvent pas diverger."""
    from apps.core.navigation import landing_route

    assert client_for(analyst).get(reverse("dashboard:home")).url == reverse(
        landing_route(analyst)
    )
