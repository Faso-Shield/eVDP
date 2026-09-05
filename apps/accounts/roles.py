"""Definition centrale des roles et des capacites RBAC.

Regle absolue : le role n'est jamais lu depuis le frontend. Il provient de la
base de donnees, via l'utilisateur authentifie. Toute verification de droit
passe par ce module.
"""

from django.db import models


class Role(models.TextChoices):
    SUPER_ADMIN = "SUPER_ADMIN", "Administrateur systeme"
    NATIONAL_COORDINATOR = "NATIONAL_COORDINATOR", "Coordinateur national"
    CSIRT_ANALYST = "CSIRT_ANALYST", "Analyste CSIRT"
    TRIAGER = "TRIAGER", "Agent de triage"
    DSI_ADMIN = "DSI_ADMIN", "Administrateur DSI"
    ORGANIZATION_MANAGER = "ORGANIZATION_MANAGER", "Responsable d'organisation"
    SECURITY_RESEARCHER = "SECURITY_RESEARCHER", "Chercheur en securite"
    BUG_BOUNTY_RESEARCHER = "BUG_BOUNTY_RESEARCHER", "Chercheur Bug Bounty"
    AUDITOR = "AUDITOR", "Auditeur"
    PUBLIC_USER = "PUBLIC_USER", "Utilisateur public"


class Capability(models.TextChoices):
    """Actions elementaires controlees par le backend."""

    VIEW_ALL_CASES = "VIEW_ALL_CASES", "Voir tous les cases"
    VIEW_ORG_CASES = "VIEW_ORG_CASES", "Voir les cases de son organisation"
    TRIAGE_CASE = "TRIAGE_CASE", "Trier un case"
    CHANGE_CASE_STATUS = "CHANGE_CASE_STATUS", "Changer le statut d'un case"
    ASSIGN_CASE = "ASSIGN_CASE", "Assigner un case"
    SET_SEVERITY = "SET_SEVERITY", "Definir la severite"
    POST_INTERNAL_MESSAGE = "POST_INTERNAL_MESSAGE", "Publier un message interne"
    MANAGE_ORGANIZATION = "MANAGE_ORGANIZATION", "Gerer une organisation"
    MANAGE_ALL_ORGANIZATIONS = "MANAGE_ALL_ORGANIZATIONS", "Gerer les organisations"
    MANAGE_PROGRAM = "MANAGE_PROGRAM", "Gerer un programme"
    SUBMIT_REPORT = "SUBMIT_REPORT", "Soumettre un rapport"
    PROPOSE_BOUNTY = "PROPOSE_BOUNTY", "Proposer une recompense"
    APPROVE_BOUNTY = "APPROVE_BOUNTY", "Approuver une recompense"
    RECORD_PAYMENT = "RECORD_PAYMENT", "Enregistrer un paiement"
    DRAFT_ADVISORY = "DRAFT_ADVISORY", "Rediger un advisory"
    PUBLISH_ADVISORY = "PUBLISH_ADVISORY", "Publier un advisory"
    VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG", "Consulter le journal d'audit"
    VIEW_NATIONAL_DASHBOARD = "VIEW_NATIONAL_DASHBOARD", "Tableau de bord national"
    VIEW_CSIRT_DASHBOARD = "VIEW_CSIRT_DASHBOARD", "Tableau de bord CSIRT"
    EXPORT_DATA = "EXPORT_DATA", "Exporter des donnees"
    IMPORT_CSAF = "IMPORT_CSAF", "Importer du CSAF"
    MANAGE_USERS = "MANAGE_USERS", "Gerer les utilisateurs"


C = Capability

#: Capacites accordees a chaque role. Aucune capacite n'est implicite.
ROLE_CAPABILITIES = {
    Role.SUPER_ADMIN: set(C.values),
    Role.NATIONAL_COORDINATOR: {
        C.VIEW_ALL_CASES,
        C.TRIAGE_CASE,
        C.CHANGE_CASE_STATUS,
        C.ASSIGN_CASE,
        C.SET_SEVERITY,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_ALL_ORGANIZATIONS,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.PROPOSE_BOUNTY,
        C.APPROVE_BOUNTY,
        C.RECORD_PAYMENT,
        C.DRAFT_ADVISORY,
        C.PUBLISH_ADVISORY,
        C.VIEW_AUDIT_LOG,
        C.VIEW_NATIONAL_DASHBOARD,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
        C.IMPORT_CSAF,
        C.MANAGE_USERS,
    },
    Role.CSIRT_ANALYST: {
        C.VIEW_ALL_CASES,
        C.TRIAGE_CASE,
        C.CHANGE_CASE_STATUS,
        C.ASSIGN_CASE,
        C.SET_SEVERITY,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_PROGRAM,
        C.PROPOSE_BOUNTY,
        C.DRAFT_ADVISORY,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
        C.IMPORT_CSAF,
    },
    Role.TRIAGER: {
        C.VIEW_ALL_CASES,
        C.TRIAGE_CASE,
        C.CHANGE_CASE_STATUS,
        C.SET_SEVERITY,
        C.POST_INTERNAL_MESSAGE,
        C.VIEW_CSIRT_DASHBOARD,
    },
    Role.DSI_ADMIN: {
        C.VIEW_ORG_CASES,
        C.CHANGE_CASE_STATUS,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.PROPOSE_BOUNTY,
        C.EXPORT_DATA,
    },
    Role.ORGANIZATION_MANAGER: {
        C.VIEW_ORG_CASES,
        C.CHANGE_CASE_STATUS,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.PROPOSE_BOUNTY,
        C.EXPORT_DATA,
    },
    Role.SECURITY_RESEARCHER: {C.SUBMIT_REPORT},
    Role.BUG_BOUNTY_RESEARCHER: {C.SUBMIT_REPORT},
    Role.AUDITOR: {
        C.VIEW_ALL_CASES,
        C.VIEW_AUDIT_LOG,
        C.VIEW_NATIONAL_DASHBOARD,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
    },
    Role.PUBLIC_USER: {C.SUBMIT_REPORT},
}

#: Roles operant au niveau national (voient l'ensemble des cases).
NATIONAL_ROLES = frozenset(
    {
        Role.SUPER_ADMIN,
        Role.NATIONAL_COORDINATOR,
        Role.CSIRT_ANALYST,
        Role.TRIAGER,
        Role.AUDITOR,
    }
)

#: Roles rattaches a une organisation (perimetre limite a leurs organisations).
ORGANIZATION_ROLES = frozenset({Role.DSI_ADMIN, Role.ORGANIZATION_MANAGER})

#: Roles chercheurs.
RESEARCHER_ROLES = frozenset(
    {Role.SECURITY_RESEARCHER, Role.BUG_BOUNTY_RESEARCHER, Role.PUBLIC_USER}
)

#: Roles pouvant etre choisis librement a l'inscription publique.
SELF_SERVICE_ROLES = frozenset({Role.SECURITY_RESEARCHER, Role.BUG_BOUNTY_RESEARCHER})

#: Roles en lecture seule : aucune ecriture metier tolerée.
READ_ONLY_ROLES = frozenset({Role.AUDITOR})


def capabilities_for(role):
    return ROLE_CAPABILITIES.get(role, set())


def role_label(role):
    return dict(Role.choices).get(role, role)
