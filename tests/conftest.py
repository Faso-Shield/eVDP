"""Fixtures partagees de la suite de tests eVDP."""

from datetime import timedelta
from decimal import Decimal

import pytest
from django.test import Client
from django.utils import timezone

from apps.accounts.middleware import SESSION_KEY as MFA_SESSION_KEY
from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.coordination.models import SLAPolicy
from apps.coordination.workflow import CaseStatus
from apps.organizations.models import (
    MembershipRole,
    Organization,
    OrganizationMember,
    OrganizationType,
    Sector,
)
from apps.programs.models import (
    ConfidentialityLevel,
    Program,
    ProgramScope,
    ProgramStatus,
    ProgramType,
    RewardPolicy,
    RewardTier,
    ScopePriority,
    ScopeTargetType,
)
from apps.reports.models import VulnerabilityReport
from apps.reports.services import submit_report
from apps.researchers.services import get_or_create_profile
from apps.vulnerabilities.constants import Severity, VulnerabilityType
from apps.vulnerabilities.models import CWE

PASSWORD = "TestPassword2026!"


@pytest.fixture(autouse=True)
def clear_rate_limit_cache():
    """Le cache locmem est partage par le processus de test.

    Sans purge, les compteurs de limitation de debit fuient d'un test a
    l'autre et provoquent des 429 inattendus.
    """
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


def make_user(email, role=Role.SECURITY_RESEARCHER, **extra):
    user = User.objects.create_user(
        email=email, password=PASSWORD, role=role, full_name=email.split("@")[0], **extra
    )
    user.email_verified = True
    user.save(update_fields=["email_verified", "updated_at"])
    return user


@pytest.fixture
def sla_policy(db):
    """Politique SLA utilisee par les tests.

    Une politique par defaut est deja creee par la migration
    coordination.0003 ; cette fixture la reutilise.
    """
    return SLAPolicy.get_default() or SLAPolicy.objects.create(
        name="SLA test", is_default=True
    )


@pytest.fixture
def organization(db):
    return Organization.objects.create(
        name="Ministere Alpha",
        acronym="ALPHA",
        organization_type=OrganizationType.MINISTRY,
        sector=Sector.HEALTH,
        domain="alpha.gov.bf",
    )


@pytest.fixture
def other_organization(db):
    return Organization.objects.create(
        name="Ministere Beta",
        acronym="BETA",
        organization_type=OrganizationType.MINISTRY,
        sector=Sector.EDUCATION,
        domain="beta.gov.bf",
    )


@pytest.fixture
def cwe(db):
    return CWE.objects.create(code="CWE-89", name="SQL Injection")


# ---------------------------------------------------------------- utilisateurs
@pytest.fixture
def coordinator(db):
    return make_user("coordinateur@test.bf", Role.NATIONAL_COORDINATOR)


@pytest.fixture
def coordinator_b(db):
    return make_user("coordinateur-b@test.bf", Role.NATIONAL_COORDINATOR)


@pytest.fixture
def analyst(db):
    return make_user("analyste@test.bf", Role.CSIRT_ANALYST)


@pytest.fixture
def triager(db):
    return make_user("triage@test.bf", Role.TRIAGER)


@pytest.fixture
def auditor(db):
    return make_user("auditeur@test.bf", Role.AUDITOR)


@pytest.fixture
def researcher_a(db):
    user = make_user("chercheur-a@test.bf", Role.SECURITY_RESEARCHER)
    get_or_create_profile(user, pseudonym="alpha-hunter")
    return user


@pytest.fixture
def researcher_b(db):
    user = make_user("chercheur-b@test.bf", Role.SECURITY_RESEARCHER)
    get_or_create_profile(user, pseudonym="beta-hunter")
    return user


@pytest.fixture
def bounty_researcher(db):
    user = make_user("bb@test.bf", Role.BUG_BOUNTY_RESEARCHER)
    get_or_create_profile(user, pseudonym="bb-hunter")
    return user


@pytest.fixture
def dsi_alpha(db, organization):
    user = make_user("dsi-alpha@test.bf", Role.DSI_ADMIN)
    OrganizationMember.objects.create(
        organization=organization, user=user, membership_role=MembershipRole.DSI
    )
    return user


@pytest.fixture
def dsi_beta(db, other_organization):
    user = make_user("dsi-beta@test.bf", Role.DSI_ADMIN)
    OrganizationMember.objects.create(
        organization=other_organization, user=user, membership_role=MembershipRole.DSI
    )
    return user


# ------------------------------------------------------------------ programmes
@pytest.fixture
def vdp_program(db, organization, sla_policy):
    program = Program.objects.create(
        name="VDP Test",
        program_type=ProgramType.VDP,
        organization=organization,
        status=ProgramStatus.ACTIVE,
        confidentiality=ConfidentialityLevel.PUBLIC,
        sla_policy=sla_policy,
        starts_on=timezone.localdate(),
    )
    ProgramScope.objects.create(
        program=program,
        in_scope=True,
        target_type=ScopeTargetType.DOMAIN,
        identifier="*.alpha.gov.bf",
    )
    return program


@pytest.fixture
def bounty_program(db, organization, sla_policy):
    program = Program.objects.create(
        name="Bug Bounty Test",
        program_type=ProgramType.BUG_BOUNTY,
        organization=organization,
        status=ProgramStatus.ACTIVE,
        confidentiality=ConfidentialityLevel.PUBLIC,
        sla_policy=sla_policy,
        starts_on=timezone.localdate(),
        allows_anonymous_reports=False,
    )
    policy = RewardPolicy.objects.create(program=program, currency="XOF")
    for severity, minimum, maximum in [
        (Severity.CRITICAL, 750000, 2000000),
        (Severity.HIGH, 300000, 750000),
        (Severity.MEDIUM, 100000, 300000),
        (Severity.LOW, 0, 100000),
    ]:
        RewardTier.objects.create(
            policy=policy,
            severity=severity,
            min_amount=Decimal(minimum),
            max_amount=Decimal(maximum),
        )
    ProgramScope.objects.create(
        program=program,
        identifier="api.exemple.bf",
        target_type=ScopeTargetType.API,
        priority=ScopePriority.P1,
    )
    ProgramScope.objects.create(
        program=program,
        identifier="vitrine.exemple.bf",
        target_type=ScopeTargetType.DOMAIN,
        priority=ScopePriority.P4,
    )
    return program


# ----------------------------------------------------------------------- cases
def evidence(name="preuve.txt", content=b"Trace de reproduction de la vulnerabilite.\n"):
    """Piece jointe minimale : exigee a toute soumission web ou API (workflow v2)."""
    from django.core.files.uploadedfile import SimpleUploadedFile

    return SimpleUploadedFile(name, content, content_type="text/plain")


def submit(report, **kwargs):
    """`submit_report` avec une preuve jointe, comme un declarant reel."""
    kwargs.setdefault("attachments", [evidence()])
    return submit_report(report, **kwargs)


def build_report(reporter, organization=None, program=None, **overrides):
    data = {
        "title": "Vulnerabilite de test",
        "product": "Portail test",
        "affected_organization": organization,
        "program": program,
        "vulnerability_type": VulnerabilityType.SQLI,
        "description": "Description suffisamment longue pour passer la validation.",
        "steps_to_reproduce": "1. Faire ceci\n2. Observer cela",
        "impact": "Acces non autorise aux donnees.",
        "reporter": reporter,
        "accepted_policy": True,
    }
    data.update(overrides)
    return VulnerabilityReport(**data)


@pytest.fixture
def case_alpha(db, researcher_a, organization, vdp_program, sla_policy):
    return submit(build_report(researcher_a, organization, vdp_program), reporter=researcher_a)


@pytest.fixture
def case_beta(db, researcher_b, other_organization, sla_policy):
    return submit(
        build_report(researcher_b, other_organization, title="Autre vulnerabilite"),
        reporter=researcher_b,
    )


@pytest.fixture
def submitted_bounty_case(db, bounty_researcher, organization, bounty_program, sla_policy):
    """Dossier Bug Bounty tout juste soumis (etape 0)."""
    return submit(
        build_report(
            bounty_researcher,
            organization,
            bounty_program,
            title="Vulnerabilite Bug Bounty",
        ),
        reporter=bounty_researcher,
    )


@pytest.fixture
def bounty_case(submitted_bounty_case):
    """Dossier Bug Bounty valide : la branche prime est ouverte (BOUNTY_ELIGIBLE)."""
    return advance(submitted_bounty_case, CaseStatus.VALIDATED)


# ------------------------------------------------------------ workflow v2
def workflow_actor(key, organization=None):
    """Acteur dedie aux helpers de workflow, distinct des fixtures de test.

    Les tests gardent ainsi leurs propres utilisateurs pour les controles
    qu'ils visent (quatre yeux, perimetre), sans collision avec ceux-ci.
    """
    roles = {
        "triager": Role.TRIAGER,
        "analyst": Role.CSIRT_ANALYST,
        "coordinator": Role.NATIONAL_COORDINATOR,
        "dsi": Role.DSI_ADMIN,
    }
    suffix = f"-{organization.pk.hex[:8]}" if organization is not None else ""
    email = f"wf-{key}{suffix}@test.bf"
    user = User.objects.filter(email=email).first()
    if user is None:
        user = make_user(email, roles[key])
        if organization is not None:
            OrganizationMember.objects.create(
                organization=organization, user=user, membership_role=MembershipRole.DSI
            )
    return user


#: Etape -> (action, role de l'acteur, donnees du formulaire).
_WORKFLOW_STEPS = {
    CaseStatus.SUBMITTED: (
        "acknowledge",
        "triager",
        {},
    ),
    CaseStatus.ACKNOWLEDGED: (
        "declare_admissible",
        "triager",
        {"in_scope": True, "organization_identified": True, "attachment_readable": True},
    ),
    CaseStatus.IN_ANALYSIS: ("submit_qualification", "analyst", {}),
    CaseStatus.VALIDATION_PENDING: (
        "validate_qualification",
        "coordinator",
        {"comment": "Qualification validee."},
    ),
    CaseStatus.VALIDATED: ("notify_vendor", "analyst", {}),
    CaseStatus.VENDOR_NOTIFIED: ("submit_remediation_plan", "dsi", None),
    CaseStatus.REMEDIATION_IN_PROGRESS: (
        "declare_fix",
        "dsi",
        {"fix_description": "Requetes parametrees.", "fix_version": "2.0.1"},
    ),
    CaseStatus.FIX_AVAILABLE: (
        "confirm_fix",
        "analyst",
        {"verification_report": "Injection non reproductible."},
    ),
    CaseStatus.FIX_VERIFIED: ("submit_advisory", "analyst", {}),
    CaseStatus.ADVISORY_REVIEW: (
        "publish_and_close",
        "coordinator",
        {"comment": "Relu.", "review_done": True},
    ),
}


def _prepare_step(case, status):
    """Remplit ce qu'une etape exige avant son bouton (hors formulaire)."""
    from apps.audit.models import AuditAction
    from apps.audit.services import log_action
    from apps.coordination.services import set_severity

    if status == CaseStatus.SUBMITTED:
        log_action(AuditAction.CASE_VIEWED, actor=workflow_actor("triager"), obj=case)
    if status == CaseStatus.IN_ANALYSIS:
        if not case.cvss_vector:
            set_severity(
                case,
                workflow_actor("analyst"),
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            )
        if case.cwe_id is None:
            case.cwe, _ = CWE.objects.get_or_create(
                code="CWE-89", defaults={"name": "SQL Injection"}
            )
            case.save(update_fields=["cwe", "updated_at"])
    if status == CaseStatus.FIX_VERIFIED:
        from apps.coordination.workflow import working_advisory
        from apps.disclosures.services import create_advisory_from_case

        if working_advisory(case) is None:
            create_advisory_from_case(
                case,
                workflow_actor("analyst"),
                summary="Une vulnerabilite corrigee affectait le portail de test.",
            )
    if status == CaseStatus.ADVISORY_REVIEW:
        _close_bounty_branch(case)


def _close_bounty_branch(case):
    """La cloture exige une branche prime terminee : proposer puis crediter."""
    from apps.coordination.services import perform_action
    from apps.coordination.workflow import BountyStage

    case.refresh_from_db()
    if case.bounty_stage == BountyStage.ELIGIBLE:
        perform_action(case, "propose_bounty", workflow_actor("analyst"))
    if case.bounty_stage == BountyStage.PROPOSED:
        perform_action(
            case, "approve_bounty", workflow_actor("coordinator"), data={"comment": "Ok."}
        )


def advance(case, target):
    """Fait avancer `case` par les boutons du workflow v2 jusqu'a `target`.

    Chaque etape est cliquee par un acteur legitime, avec ses pre-requis :
    les controles du moteur (capacite, pre-requis, quatre yeux) s'appliquent
    comme en production.
    """
    from apps.coordination.services import perform_action
    from apps.coordination.workflow import MAIN_PATH

    case.refresh_from_db()
    while MAIN_PATH.index(case.status) < MAIN_PATH.index(target):
        status = case.status
        action, role, data = _WORKFLOW_STEPS[status]
        _prepare_step(case, status)
        if data is None:
            data = {
                "remediation_plan": "Corriger la requete et deployer.",
                "remediation_target_date": timezone.localdate() + timedelta(days=20),
            }
        organization = case.organization if role == "dsi" else None
        perform_action(case, action, workflow_actor(role, organization), data=dict(data))
        case.refresh_from_db()
    return case


# ---------------------------------------------------------------------- client
@pytest.fixture
def client_for(db):
    """Client connecte, session elevee comme apres un second facteur valide.

    Un compte non signaleur n'accede a rien tant que sa session n'a pas ete
    elevee par un code TOTP (voir apps.accounts.middleware). `force_login`
    ne fait que la moitie du chemin : sans cette elevation, chaque test de
    RBAC ou d'API mesurerait le refus du second facteur au lieu de ce qu'il
    veut verifier. Passer `mfa=False` rend le client non eleve, pour les
    tests qui visent precisement ce refus.
    """

    def _client(user=None, mfa=True):
        client = Client()
        if user is not None:
            client.force_login(user)
            if mfa:
                session = client.session
                session[MFA_SESSION_KEY] = True
                session.save()
        return client

    return _client
