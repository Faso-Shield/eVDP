"""Menu lateral de l'espace authentifie.

Le menu etait pose en dur dans le gabarit : tout le monde voyait Coordination,
Kanban, Journal d'audit et Redaction d'advisories, y compris un signaleur qui
n'a acces a aucun des quatre. Un menu qui annonce ce qu'il ne peut pas ouvrir
apprend au lecteur a se mefier de ce qu'il lit.

Chaque entree declare donc la capacite qu'elle exige, et le menu se deduit du
role — jamais du client. Les capacites sont celles que les vues ciblees
controlent deja ; les deux listes ne doivent pas diverger.

Un titre de section n'apparait que si la section a du contenu, faute de quoi
une rubrique vide signalerait un droit manquant plutot qu'un droit absent.

Les libelles portent leurs accents, contrairement au reste des sources
Python du depot : ce sont les intitules que l'utilisateur lit, ils etaient
accentues dans le gabarit, et les en priver serait une regression visible.
Commentaires et docstrings suivent la convention.
"""

from django.urls import reverse

from apps.accounts.roles import Capability

C = Capability


def _lien(libelle, nom_url):
    return {"label": libelle, "url": reverse(nom_url)}


def sidebar_sections(user):
    """Sections du menu pour `user`, vides s'il n'est pas authentifie.

    Rend une liste de `(titre, liens)`. Le titre vaut None pour une entree
    isolee, qui ne merite pas de rubrique a elle seule.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return []

    peut = user.has_capability
    voit_des_dossiers = peut(C.VIEW_ALL_CASES) or peut(C.VIEW_ORG_CASES)
    sections = []

    espace = [_lien("Tableau de bord", "dashboard:home")]
    if peut(C.VIEW_CSIRT_DASHBOARD):
        espace.append(_lien("Vue CSIRT", "dashboard:csirt"))
    if user.is_organization_user:
        espace.append(_lien("Vue organisation", "dashboard:organization"))
    if user.is_researcher:
        espace.append(_lien("Espace chercheur", "dashboard:researcher"))
    sections.append(("Espace", espace))

    # Un signaleur atteint ses propres dossiers depuis son espace ; la
    # rubrique Coordination est l'outil de ceux qui traitent ceux d'autrui.
    if voit_des_dossiers:
        sections.append(
            (
                "Coordination",
                [
                    _lien("Dossiers", "coordination:case_list"),
                    _lien("Kanban", "coordination:kanban"),
                    _lien("Recherche globale", "dashboard:search"),
                ],
            )
        )

    bug_bounty = [_lien("Récompenses", "bounty:list")]
    if peut(C.MANAGE_PROGRAM):
        bug_bounty.append(_lien("Mes programmes", "programs:my_programs"))
    sections.append(("Bug Bounty", bug_bounty))

    publication = [_lien("Advisories publiés", "disclosures:advisory_list")]
    if peut(C.DRAFT_ADVISORY):
        publication.append(_lien("Rédaction d'advisories", "disclosures:manage_list"))
    sections.append(("Publication", publication))

    administration = []
    if peut(C.MANAGE_ORGANIZATION) or peut(C.MANAGE_ALL_ORGANIZATIONS):
        administration.append(_lien("Organisations", "organizations:manage_list"))
    if peut(C.VIEW_AUDIT_LOG):
        administration.append(_lien("Journal d'audit", "audit:list"))
    if user.is_staff:
        administration.append({"label": "Administration Django", "url": "/admin/"})
    if administration:
        sections.append(("Administration", administration))

    # Hors rubrique : le profil n'appartient pas a l'administration, et il
    # etait le seul lien que tout le monde y trouvait.
    sections.append((None, [_lien("Mon profil", "accounts:profile")]))
    return sections
