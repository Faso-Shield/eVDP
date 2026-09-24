"""Definition centrale des roles et des capacites RBAC.

Regle absolue : le role n'est jamais lu depuis le frontend. Il provient de la
base de donnees, via l'utilisateur authentifie. Toute verification de droit
passe par ce module.
"""

from django.db import models


class Role(models.TextChoices):
    SUPER_ADMIN = "SUPER_ADMIN", "Administrateur système"
    NATIONAL_COORDINATOR = "NATIONAL_COORDINATOR", "Coordinateur national"
    CSIRT_ANALYST = "CSIRT_ANALYST", "Analyste CSIRT"
    TRIAGER = "TRIAGER", "Agent de triage"
    DSI_ADMIN = "DSI_ADMIN", "Administrateur DSI"
    ORGANIZATION_MANAGER = "ORGANIZATION_MANAGER", "Responsable d'organisation"
    SECURITY_RESEARCHER = "SECURITY_RESEARCHER", "Chercheur en sécurité"
    BUG_BOUNTY_RESEARCHER = "BUG_BOUNTY_RESEARCHER", "Chercheur Bug Bounty"
    AUDITOR = "AUDITOR", "Auditeur"
    PUBLIC_USER = "PUBLIC_USER", "Utilisateur public"


class Capability(models.TextChoices):
    """Actions elementaires controlees par le backend.

    Workflow v2 (SPEC-eVDP-2026-V2) : chaque bouton du dossier est porte par
    une capacite distincte, pour qu'une etape n'ait qu'un seul proprietaire.
    """

    VIEW_ALL_CASES = "VIEW_ALL_CASES", "Voir tous les cases"
    VIEW_ORG_CASES = "VIEW_ORG_CASES", "Voir les cases de son organisation"
    TRIAGE_CASE = "TRIAGE_CASE", "Trier un case (accuser réception, recevabilité)"
    CHANGE_CASE_STATUS = "CHANGE_CASE_STATUS", "Planifier la divulgation, associer un CVE"
    ASSIGN_CASE = "ASSIGN_CASE", "Assigner un case"
    SET_SEVERITY = "SET_SEVERITY", "Qualifier un case (saisie CVSS, CWE)"
    VALIDATE_SEVERITY = "VALIDATE_SEVERITY", "Valider une qualification"
    REQUEST_INFORMATION = "REQUEST_INFORMATION", "Demander des compléments"
    PROVIDE_INFORMATION = "PROVIDE_INFORMATION", "Envoyer des compléments"
    PROPOSE_REJECTION = "PROPOSE_REJECTION", "Proposer un rejet ou un doublon"
    CONFIRM_REJECTION = "CONFIRM_REJECTION", "Confirmer un rejet ou un doublon"
    SEND_BACK = "SEND_BACK", "Renvoyer une étape à son auteur"
    ESCALATE_CASE = "ESCALATE_CASE", "Escalader un case"
    NOTIFY_VENDOR = "NOTIFY_VENDOR", "Transmettre à l'organisation"
    MANAGE_REMEDIATION = "MANAGE_REMEDIATION", "Piloter la remédiation"
    VERIFY_FIX = "VERIFY_FIX", "Vérifier un correctif"
    POST_INTERNAL_MESSAGE = "POST_INTERNAL_MESSAGE", "Publier un message interne"
    MANAGE_ORGANIZATION = "MANAGE_ORGANIZATION", "Gérer une organisation"
    MANAGE_ALL_ORGANIZATIONS = "MANAGE_ALL_ORGANIZATIONS", "Gérer les organisations"
    MANAGE_PROGRAM = "MANAGE_PROGRAM", "Gérer un programme"
    SUBMIT_REPORT = "SUBMIT_REPORT", "Soumettre un rapport"
    PROPOSE_BOUNTY = "PROPOSE_BOUNTY", "Proposer une récompense"
    APPROVE_BOUNTY = "APPROVE_BOUNTY", "Approuver une récompense"
    RECORD_PAYMENT = "RECORD_PAYMENT", "Enregistrer un paiement"
    DRAFT_ADVISORY = "DRAFT_ADVISORY", "Rédiger un advisory"
    PUBLISH_ADVISORY = "PUBLISH_ADVISORY", "Publier un advisory"
    VIEW_AUDIT_LOG = "VIEW_AUDIT_LOG", "Consulter le journal d'audit"
    VIEW_NATIONAL_DASHBOARD = "VIEW_NATIONAL_DASHBOARD", "Tableau de bord national"
    VIEW_CSIRT_DASHBOARD = "VIEW_CSIRT_DASHBOARD", "Tableau de bord CSIRT"
    EXPORT_DATA = "EXPORT_DATA", "Exporter des données"
    IMPORT_CSAF = "IMPORT_CSAF", "Importer du CSAF"
    MANAGE_USERS = "MANAGE_USERS", "Gérer les utilisateurs"


C = Capability

#: Capacites de l'administration technique. Le Super admin n'a qu'elles :
#: il gere comptes, roles, configuration, SLA et matrices de prime, mais ne
#: lit aucun dossier et ne clique aucun bouton de workflow (ISO/IEC 27001
#: A.5.3, separation des taches).
ADMINISTRATION_CAPABILITIES = frozenset(
    {
        C.MANAGE_USERS,
        C.MANAGE_ALL_ORGANIZATIONS,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.VIEW_AUDIT_LOG,
    }
)

#: Capacites accordees a chaque role. Aucune capacite n'est implicite.
ROLE_CAPABILITIES = {
    Role.SUPER_ADMIN: set(ADMINISTRATION_CAPABILITIES),
    # Vue nationale administrative et financiere : valide, confirme, publie,
    # approuve. Ne saisit ni CVSS ni advisory : il relit le travail d'autrui.
    Role.NATIONAL_COORDINATOR: {
        C.VIEW_ALL_CASES,
        C.CHANGE_CASE_STATUS,
        C.ASSIGN_CASE,
        C.VALIDATE_SEVERITY,
        C.CONFIRM_REJECTION,
        C.SEND_BACK,
        C.ESCALATE_CASE,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_ALL_ORGANIZATIONS,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.APPROVE_BOUNTY,
        C.RECORD_PAYMENT,
        C.PUBLISH_ADVISORY,
        C.VIEW_AUDIT_LOG,
        C.VIEW_NATIONAL_DASHBOARD,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
        C.IMPORT_CSAF,
        C.MANAGE_USERS,
    },
    # Seul a saisir le CVSS ; echange avec le chercheur et l'organisation.
    Role.CSIRT_ANALYST: {
        C.VIEW_ALL_CASES,
        C.CHANGE_CASE_STATUS,
        C.ASSIGN_CASE,
        C.SET_SEVERITY,
        C.REQUEST_INFORMATION,
        C.PROPOSE_REJECTION,
        C.NOTIFY_VENDOR,
        C.VERIFY_FIX,
        C.POST_INTERNAL_MESSAGE,
        C.MANAGE_PROGRAM,
        C.PROPOSE_BOUNTY,
        C.DRAFT_ADVISORY,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
        C.IMPORT_CSAF,
    },
    # Spec v2 : plus de saisie CVSS pour le triage.
    Role.TRIAGER: {
        C.VIEW_ALL_CASES,
        C.TRIAGE_CASE,
        C.REQUEST_INFORMATION,
        C.PROPOSE_REJECTION,
        C.POST_INTERNAL_MESSAGE,
        C.VIEW_CSIRT_DASHBOARD,
    },
    # La DSI pilote la remediation ; elle ne rejette pas, ne voit pas le
    # Wallet et ne propose pas de prime.
    Role.DSI_ADMIN: {
        C.VIEW_ORG_CASES,
        C.MANAGE_REMEDIATION,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.EXPORT_DATA,
    },
    Role.ORGANIZATION_MANAGER: {
        C.VIEW_ORG_CASES,
        C.MANAGE_REMEDIATION,
        C.MANAGE_ORGANIZATION,
        C.MANAGE_PROGRAM,
        C.EXPORT_DATA,
    },
    Role.SECURITY_RESEARCHER: {C.SUBMIT_REPORT, C.PROVIDE_INFORMATION},
    Role.BUG_BOUNTY_RESEARCHER: {C.SUBMIT_REPORT, C.PROVIDE_INFORMATION},
    Role.AUDITOR: {
        C.VIEW_ALL_CASES,
        C.VIEW_AUDIT_LOG,
        C.VIEW_NATIONAL_DASHBOARD,
        C.VIEW_CSIRT_DASHBOARD,
        C.EXPORT_DATA,
    },
    Role.PUBLIC_USER: {C.SUBMIT_REPORT, C.PROVIDE_INFORMATION},
}

#: Capacites attribuables individuellement, en plus du role, sans creer de
#: role supplementaire. Un analyste senior recoit VALIDATE_SEVERITY pour
#: l'etape 4 ; la regle des quatre yeux l'empeche toujours de valider sa
#: propre qualification.
SENIOR_ANALYST_CAPABILITIES = frozenset({C.VALIDATE_SEVERITY})

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

#: Roles metiers et administrateurs : le complement des roles signaleurs.
#:
#: Defini par difference et non par enumeration : un role ajoute a `Role`
#: rejoint cette population par defaut, ce qui est le sens sur : il faut une
#: decision explicite pour dispenser un role du second facteur et le ranger
#: parmi les signaleurs. Frontiere unique, lue par la double authentification
#: (`apps.accounts.mfa.is_required`) comme par les deux listes de comptes de
#: l'administration.
BUSINESS_ROLES = frozenset(set(Role.values) - set(RESEARCHER_ROLES))

#: Roles en lecture seule : aucune ecriture metier tolerée.
READ_ONLY_ROLES = frozenset({Role.AUDITOR})


def capabilities_for(role):
    return ROLE_CAPABILITIES.get(role, set())


def role_label(role):
    return dict(Role.choices).get(role, role)
