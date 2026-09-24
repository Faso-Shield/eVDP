"""Service de soumission d'un rapport de vulnerabilite.

C'est le point d'entree unique (formulaire web, API, import CSAF). Il cree le
rapport, ouvre le Case correspondant, initialise la chronologie, les
participants, les SLA et notifie les parties prenantes.
"""

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.constants import ParticipantRole, TimelineEventType, WorkflowType
from apps.coordination.models import Case
from apps.coordination.services import (
    add_participant,
    add_timeline_event,
    ensure_default_participants,
    generate_tracking_token,
    schedule_initial_sla,
)
from apps.coordination.workflow import CaseStatus
from apps.core.middleware import get_client_ip
from apps.core.utils import hash_text
from apps.notifications.models import NotificationKind
from apps.notifications.services import notify_external
from apps.programs.models import ProgramType
from apps.vulnerabilities.constants import ReportSource, Severity
from apps.vulnerabilities.cvss import CVSSError, evaluate, score_as_decimal

from .models import ReportStatus, VulnerabilityReport

#: Canaux de soumission d'un declarant : une piece jointe y est exigee
#: (workflow v2, etape 0). L'import CSAF et la saisie interne en sont exemptes :
#: ils reprennent un avis deja publie, pas une preuve de declarant.
ATTACHMENT_REQUIRED_SOURCES = (ReportSource.WEB, ReportSource.API)

#: Nombre maximal de fichiers joints a la soumission.
MAX_SUBMISSION_FILES = 5


def _workflow_for(program):
    if program and program.program_type == ProgramType.BUG_BOUNTY:
        return WorkflowType.BUG_BOUNTY
    return WorkflowType.VDP


def _severity_for(report):
    if report.cvss_vector:
        try:
            score, severity = evaluate(report.cvss_vector)
            return severity, score_as_decimal(score)
        except CVSSError:
            pass
    return report.reported_severity or Severity.MEDIUM, report.cvss_score


def may_report(user):
    """Qui peut declarer une vulnerabilite (web et API).

    Un signaleur anonyme (sans compte), ou un compte chercheur : chercheur,
    chercheur Bug Bounty ou utilisateur public (capacite SUBMIT_REPORT).
    Jamais un compte metier : il traite les signalements, il ne les emet pas.
    L'import CSAF, geste de l'analyste, n'est pas un signalement.
    """
    from apps.accounts.roles import Capability

    if user is None or not user.is_authenticated:
        return True
    return user.has_capability(Capability.SUBMIT_REPORT)


def _check_attachments(files, source):
    """Controle serveur : au moins une piece jointe valide (web et API)."""
    from apps.attachments.services import validate_upload

    files = list(files or [])
    if source in ATTACHMENT_REQUIRED_SOURCES and not files:
        raise ValidationError(
            {"attachments": "Au moins une pièce jointe est obligatoire pour soumettre un rapport."}
        )
    if len(files) > MAX_SUBMISSION_FILES:
        raise ValidationError(
            {"attachments": f"{MAX_SUBMISSION_FILES} pièces jointes au maximum à la soumission."}
        )
    # Tous les fichiers sont valides avant d'ecrire quoi que ce soit : un
    # rapport n'est jamais cree avec une partie seulement de ses preuves.
    for uploaded in files:
        try:
            validate_upload(uploaded)
        except ValidationError as exc:
            raise ValidationError(
                {"attachments": f"Pièce jointe « {uploaded.name} » refusée : "
                 + "; ".join(exc.messages)}
            ) from exc
        uploaded.seek(0)
    return files


@transaction.atomic
def submit_report(
    report, request=None, source=ReportSource.WEB, reporter=None, attachments=None
):
    """Enregistre un rapport soumis et cree le Case associe.

    Le rapport reste prive : aucune donnee n'est rendue publique ici.
    `attachments` : fichiers televerses avec le rapport. Au moins un est exige
    pour le formulaire web et l'API (controle serveur, pas seulement HTML).
    """
    files = _check_attachments(attachments, source)
    if (
        source in ATTACHMENT_REQUIRED_SOURCES
        and reporter is not None
        and reporter.is_authenticated
        and not may_report(reporter)
    ):
        raise PermissionDenied(
            "Les comptes métiers ne déclarent pas de vulnérabilité : le signalement "
            "est réservé aux chercheurs et aux signaleurs anonymes."
        )
    if reporter is not None and reporter.is_authenticated:
        report.reporter = reporter

    # Conditions d'acces du programme. Controlees ici et non seulement dans le
    # formulaire : ce service est le point d'entree commun au web, a l'API et
    # a l'import CSAF, et la regle doit valoir pour les trois.
    if report.program_id is not None:
        motif = report.program.reporter_rejection(
            report.reporter, is_anonymous=report.is_anonymous
        )
        if motif:
            raise ValidationError({"program": motif})

    report.source = source
    report.status = ReportStatus.SUBMITTED
    report.submitted_at = timezone.now()
    if request is not None:
        client_ip = get_client_ip(request)
        if client_ip:
            report.submitter_ip_hash = hash_text(client_ip)
    # Un ModelSerializer et un import ne declenchent pas la validation du
    # modele : sans cet appel, VulnerabilityReport.clean() ne s'executait que
    # pour le formulaire web, seul chemin a passer par un ModelForm. Le
    # controle du bloc PGP est ici le seul garde-fou de l'API.
    report.full_clean()
    report.save()

    severity, score = _severity_for(report)
    organization = report.affected_organization
    if organization is None and report.program_id:
        organization = report.program.organization

    case = Case.objects.create(
        report=report,
        workflow=_workflow_for(report.program),
        program=report.program,
        title=report.title,
        reporter=report.reporter,
        organization=organization,
        product=report.product,
        vulnerability_type=report.vulnerability_type,
        severity=severity,
        cvss_score=score,
        cvss_vector=report.cvss_vector,
        cwe=report.cwe,
        status=CaseStatus.SUBMITTED,
    )

    add_timeline_event(
        case,
        TimelineEventType.REPORT_RECEIVED,
        "Rapport recu",
        actor=report.reporter,
        occurred_at=report.submitted_at,
    )
    if report.reporter_id:
        add_participant(case, report.reporter, ParticipantRole.REPORTER)
    ensure_default_participants(case)
    schedule_initial_sla(case)
    case.refresh_priority()

    from apps.attachments.services import store_attachment

    uploader = reporter if reporter is not None and reporter.is_authenticated else None
    for uploaded in files:
        store_attachment(uploaded, uploader, case=case, report=report, request=request)

    log_action(
        AuditAction.REPORT_SUBMITTED,
        actor=report.reporter,
        obj=case,
        request=request,
        source=source,
        program=report.program.name if report.program_id else None,
        anonymous=report.is_anonymous,
    )
    log_action(
        AuditAction.CASE_CREATED,
        actor=report.reporter,
        obj=case,
        request=request,
        severity=case.severity,
    )

    _notify_new_case(case, report)
    return case


def _notify_new_case(case, report):
    """Avise l'equipe de coordination et accuse reception au declarant.

    Un declarant sans compte (avec ou sans email) recoit un jeton de suivi
    lui permettant de consulter l'avancement de son dossier sans jamais
    creer de compte ni lever son anonymat. La valeur en clair transite une
    seule fois : par email s'il a laisse un contact, sinon elle est exposee
    sur `case.tracking_token_raw` pour un affichage unique a l'ecran (voir
    apps.reports.views.submit).
    """
    from apps.coordination.services import notify_step_owners

    # Etape 1 : seuls les responsables (agents de triage) sont avises, dans
    # la plateforme et par email -- pas toute l'equipe nationale.
    notify_step_owners(case)

    if report.reporter_id:
        from apps.notifications.services import notify

        notify(report.reporter, NotificationKind.ACKNOWLEDGEMENT, case=case)
        return

    raw_token = generate_tracking_token(case)
    case.tracking_token_raw = raw_token
    if report.reporter_email:
        notify_external(
            report.reporter_email,
            NotificationKind.TRACKING_LINK,
            case=case,
            url=f"/suivi/{raw_token}/",
        )


def reports_for(user):
    """Rapports visibles par l'utilisateur (isolation stricte)."""
    if not user or not user.is_authenticated:
        return VulnerabilityReport.objects.none()
    if user.is_national:
        return VulnerabilityReport.objects.all()
    case_ids = Case.objects.visible_to(user).values_list("report_id", flat=True)
    return VulnerabilityReport.objects.filter(
        pk__in=case_ids
    ) | VulnerabilityReport.objects.filter(reporter=user)
