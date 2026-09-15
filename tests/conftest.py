"""Fixtures partagees de la suite de tests eVDP."""

from decimal import Decimal

import pytest
from django.test import Client
from django.utils import timezone

from apps.accounts.models import User
from apps.accounts.roles import Role
from apps.coordination.models import SLAPolicy
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
    return program


# ----------------------------------------------------------------------- cases
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
    return submit_report(
        build_report(researcher_a, organization, vdp_program), reporter=researcher_a
    )


@pytest.fixture
def case_beta(db, researcher_b, other_organization, sla_policy):
    return submit_report(
        build_report(researcher_b, other_organization, title="Autre vulnerabilite"),
        reporter=researcher_b,
    )


@pytest.fixture
def bounty_case(db, bounty_researcher, organization, bounty_program, sla_policy):
    return submit_report(
        build_report(
            bounty_researcher,
            organization,
            bounty_program,
            title="Vulnerabilite Bug Bounty",
        ),
        reporter=bounty_researcher,
    )


# ---------------------------------------------------------------------- client
@pytest.fixture
def client_for(db):
    def _client(user=None):
        client = Client()
        if user is not None:
            client.force_login(user)
        return client

    return _client
