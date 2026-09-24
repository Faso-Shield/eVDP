"""Matrice de visibilite des donnees d'un dossier (workflow v2).

Chaque role ne voit que ce que son etape exige. Ce module est la source
unique de ces regles : la fiche du dossier, la messagerie, le telechargement
des pieces jointes et l'API s'y referent, afin qu'aucune vue ne decide seule.

Legende de la matrice : WRITE = lecture et ecriture, READ = lecture seule,
PARTIAL = voir la note de la donnee, None = aucun acces.
"""

import hashlib

from apps.accounts.roles import Role

from .constants import Confidentiality
from .workflow import ORG_VISIBLE_STATES, public_status_bucket

WRITE = "write"
READ = "read"
PARTIAL = "partial"

REPORTER = "reporter"
TRIAGER = "triager"
ANALYST = "analyst"
COORDINATOR = "coordinator"
VENDOR = "vendor"
AUDITOR = "auditor"


def viewer_kind(case, user):
    """Categorie de lecteur au sens de la matrice (None : aucun acces)."""
    if not user or not user.is_authenticated or not case.is_visible_to(user):
        return None
    if case.reporter_id == user.pk:
        return REPORTER
    role = user.role
    if role == Role.NATIONAL_COORDINATOR:
        return COORDINATOR
    if role == Role.CSIRT_ANALYST:
        return ANALYST
    if role == Role.TRIAGER:
        return TRIAGER
    if role == Role.AUDITOR:
        return AUDITOR
    if user.is_organization_user:
        return VENDOR
    return None


#: Donnee -> {categorie: niveau}. Les absents n'ont aucun acces.
MATRIX = {
    "report": {
        REPORTER: READ,
        TRIAGER: READ,
        ANALYST: READ,
        COORDINATOR: READ,
        VENDOR: READ,  # a partir de l'etape 5, garanti par is_visible_to
        AUDITOR: PARTIAL,  # metadonnees seulement
    },
    "identity": {
        REPORTER: WRITE,
        TRIAGER: READ,
        ANALYST: READ,
        COORDINATOR: READ,
        VENDOR: PARTIAL,  # pseudonyme ou rien selon le mode
        AUDITOR: PARTIAL,  # pseudonymisee
    },
    "cvss": {
        TRIAGER: READ,
        ANALYST: WRITE,
        COORDINATOR: READ,
        VENDOR: PARTIAL,  # score final
        AUDITOR: READ,
    },
    "notes": {TRIAGER: WRITE, ANALYST: WRITE, COORDINATOR: READ, AUDITOR: READ},
    Confidentiality.RESEARCHER: {
        REPORTER: WRITE,
        TRIAGER: WRITE,
        ANALYST: WRITE,
        COORDINATOR: WRITE,
        AUDITOR: READ,
    },
    Confidentiality.ORGANIZATION: {
        ANALYST: WRITE,
        COORDINATOR: WRITE,
        VENDOR: WRITE,
        AUDITOR: READ,
    },
    "wallet": {ANALYST: PARTIAL, COORDINATOR: WRITE, AUDITOR: READ},
    "advisory": {ANALYST: WRITE, COORDINATOR: WRITE, VENDOR: READ, AUDITOR: READ},
    # Suivi interne : statuts detailles, SLA, historique, participants.
    "tracking": {
        TRIAGER: READ,
        ANALYST: READ,
        COORDINATOR: READ,
        VENDOR: READ,
        AUDITOR: READ,
    },
}

#: Les notes de triage et d'analyse circulent dans le canal INTERNAL.
MATRIX[Confidentiality.INTERNAL] = MATRIX["notes"]


def level(case, user, data, kind=None):
    kind = kind if kind is not None else viewer_kind(case, user)
    if kind is None:
        return None
    return MATRIX.get(data, {}).get(kind)


def readable_channels(case, user):
    kind = viewer_kind(case, user)
    return {
        channel
        for channel in Confidentiality.values
        if level(case, user, channel, kind) in (READ, WRITE)
    }


def writable_channels(case, user):
    if getattr(user, "is_read_only", False):
        return []
    kind = viewer_kind(case, user)
    if kind == VENDOR and case.status not in ORG_VISIBLE_STATES:
        return []
    return [
        channel for channel in Confidentiality.values if level(case, user, channel, kind) == WRITE
    ]


def pseudonymize(case):
    """Identifiant stable et non reversible du declarant, pour l'auditeur."""
    seed = str(case.reporter_id or case.report_id or case.pk)
    return "Déclarant #" + hashlib.sha256(seed.encode()).hexdigest()[:8].upper()


def protected_identity(case):
    """Identite du declarant vue par l'organisation : pseudonyme ou rien."""
    from apps.researchers.models import IdentityMode

    report = case.report
    if report.is_anonymous or case.reporter_id is None:
        return None
    profile = getattr(case.reporter, "researcher_profile", None)
    if profile is None or profile.identity_mode == IdentityMode.PRIVATE:
        return None
    return profile.pseudonym or None


def reporter_label(case, user, kind=None):
    kind = kind if kind is not None else viewer_kind(case, user)
    access = level(case, user, "identity", kind)
    if access in (READ, WRITE):
        return case.report.reporter_display
    if kind == AUDITOR:
        return pseudonymize(case)
    if kind == VENDOR:
        return protected_identity(case) or "Identité protégée"
    return None


def case_view(case, user):
    """Ce que la fiche du dossier doit montrer a cet utilisateur."""
    kind = viewer_kind(case, user)
    get = lambda data: level(case, user, data, kind)  # noqa: E731
    simplified = kind == REPORTER
    bucket_key, bucket_label = public_status_bucket(case.status)
    return {
        "kind": kind,
        "is_reporter": kind == REPORTER,
        "report_body": get("report") == READ,
        "attachments_download": get("report") == READ,
        "attachments_listed": get("report") is not None,
        "reporter_label": reporter_label(case, user, kind),
        "cvss": get("cvss"),
        "notes": get("notes"),
        "wallet": get("wallet"),
        "advisory": get("advisory"),
        "tracking": get("tracking") is not None,
        "simplified_status": simplified,
        "status_label": bucket_label if simplified else case.get_status_display(),
        "status_key": bucket_key,
        "readable_channels": readable_channels(case, user),
        "writable_channels": writable_channels(case, user),
    }


def can_download_attachment(case, user):
    return level(case, user, "report") == READ
