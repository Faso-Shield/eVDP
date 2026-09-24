"""Service de soumission d'un rapport de vulnerabilite.

C'est le point d'entree unique (formulaire web, API, import CSAF). Il cree le
rapport, ouvre le Case correspondant, initialise la chronologie, les
participants, les SLA et notifie les parties prenantes.
"""

from django.core.exceptions import ValidationError
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
from apps.notifications.services import notify_external, notify_many
from apps.programs.models import ProgramType
from apps.vulnerabilities.constants import ReportSource, Severity
from apps.vulnerabilities.cvss import CVSSError, evaluate, score_as_decimal

from .models import ReportStatus, VulnerabilityReport


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


#: Sources humaines : le declarant doit joindre au moins une piece (spec v2,
#: etape 0). Un import CSAF est un document machine, sans preuve jointe.
SOURCES_REQUIRING_ATTACHMENT = frozenset({ReportSource.WEB, ReportSource.API})

#: Nombre maximal de pieces jointes transmises avec la soumission.
MAX_SUBMISSION_ATTACHMENTS = 5


def validate_submission_attachments(attachments, source=ReportSource.WEB):
    """Controle serveur des pieces jointes d'une soumission.

    Au moins une piece est exigee pour une soumission web ou API ; chaque
    fichier est valide (taille, extension, MIME, signature) AVANT toute
    ecriture, pour qu'un refus ne laisse ni rapport ni case orphelin.
    """
    from apps.attachments.services import validate_upload

    attachments = list(attachments or [])
    if source in SOURCES_REQUIRING_ATTACHMENT and not attachments:
        raise ValidationError(
            {
                "attachments": "Au moins une pièce jointe est obligatoire pour soumettre un rapport."
            }
        )
    if len(attachments) > MAX_SUBMISSION_ATTACHMENTS:
        raise ValidationError(
            {"attachments": f"{MAX_SUBMISSION_ATTACHMENTS} pièces jointes au maximum."}
        )
    for uploaded in attachments:
        try:
            validate_upload(uploaded)
        except ValidationError as exc:
            raise ValidationError(
                {"attachments": f"« {uploaded.name} » refusé : {'; '.join(exc.messages)}"}
            ) from exc
    return attachments


@transaction.atomic
def submit_report(
    report, request=None, source=ReportSource.WEB, reporter=None, attachments=None
):
    """Enregistre un rapport soumis et cree le Case associe.

    Le rapport reste prive : aucune donnee n'est rendue publique ici. Les
    pieces jointes du declarant sont enregistrees dans la meme transaction :
    elles sont ensuite en lecture seule pour tous les roles.
    """
    if reporter is not None and reporter.is_authenticated:
        report.reporter = reporter
    attachments = validate_submission_attachments(attachments, source)

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

    if attachments:
        from apps.attachments.services import store_attachment

        uploader = report.reporter if report.reporter_id else None
        for uploaded in attachments:
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
    from apps.accounts.models import User
    from apps.accounts.roles import Role

    triage_team = User.objects.filter(
        is_active=True,
        role__in=[Role.CSIRT_ANALYST, Role.TRIAGER, Role.NATIONAL_COORDINATOR],
    )
    notify_many(triage_team, NotificationKind.REPORT_RECEIVED, case=case)

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
    if user.can_view_all_cases:
        return VulnerabilityReport.objects.all()
    case_ids = Case.objects.visible_to(user).values_list("report_id", flat=True)
    return VulnerabilityReport.objects.filter(
        pk__in=case_ids
    ) | VulnerabilityReport.objects.filter(reporter=user)
