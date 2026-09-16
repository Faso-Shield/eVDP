"""Tests de gestion des programmes : creation, edition, coherence RewardPolicy."""

import pytest
from django.urls import reverse

from apps.programs.models import Program, ProgramType

pytestmark = pytest.mark.django_db


def manage_payload(program, **overrides):
    payload = {
        "name": program.name,
        "program_type": program.program_type,
        "organization": program.organization_id,
        "status": program.status,
        "confidentiality": program.confidentiality,
        "summary": program.summary,
        "description": program.description,
        "rules": program.rules,
        "out_of_scope_notes": program.out_of_scope_notes,
        "safe_harbor": program.safe_harbor,
        "disclosure_policy": program.disclosure_policy,
        "eligibility": program.eligibility,
        "contact_email": program.contact_email,
        "pgp_public_key": program.pgp_public_key,
        "sla_policy": program.sla_policy_id or "",
        "disclosure_delay_days": program.disclosure_delay_days,
        "requires_verified_email": "on" if program.requires_verified_email else "",
        "allows_anonymous_reports": "on" if program.allows_anonymous_reports else "",
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------- coherence RewardPolicy
def test_switching_program_to_bounty_creates_active_reward_policy(
    client_for, coordinator, vdp_program
):
    """Regression : passer un programme de VDP a Bug Bounty ne creait sa
    RewardPolicy qu'au rechargement suivant, jamais dans la meme requete."""
    client = client_for(coordinator)
    response = client.post(
        reverse("programs:manage", args=[vdp_program.slug]),
        manage_payload(vdp_program, program_type=ProgramType.BUG_BOUNTY),
    )
    assert response.status_code == 302
    vdp_program.refresh_from_db()
    assert vdp_program.program_type == ProgramType.BUG_BOUNTY
    policy = vdp_program.reward_policy
    assert policy.is_active is True


def test_switching_program_away_from_bounty_deactivates_reward_policy(
    client_for, coordinator, bounty_program
):
    """Regression : repasser un programme Bug Bounty en VDP laissait une
    RewardPolicy perimee toujours active (et donc affichable). Les paliers
    existants (TOTAL_FORMS) sont echoes tels quels : seul program_type change."""
    assert bounty_program.reward_policy.is_active is True
    tier_count = bounty_program.reward_policy.tiers.count()
    assert tier_count > 0
    client = client_for(coordinator)
    formset_management = {
        "tiers-TOTAL_FORMS": str(tier_count),
        "tiers-INITIAL_FORMS": str(tier_count),
        "tiers-MIN_NUM_FORMS": "0",
        "tiers-MAX_NUM_FORMS": "1000",
    }
    for i, tier in enumerate(bounty_program.reward_policy.tiers.all()):
        formset_management[f"tiers-{i}-id"] = str(tier.pk)
        formset_management[f"tiers-{i}-severity"] = tier.severity
        formset_management[f"tiers-{i}-min_amount"] = str(tier.min_amount)
        formset_management[f"tiers-{i}-max_amount"] = str(tier.max_amount)
        formset_management[f"tiers-{i}-description"] = tier.description
    response = client.post(
        reverse("programs:manage", args=[bounty_program.slug]),
        {
            **manage_payload(bounty_program, program_type=ProgramType.VDP),
            **formset_management,
        },
    )
    assert response.status_code == 302
    bounty_program.refresh_from_db()
    assert bounty_program.program_type == ProgramType.VDP
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is False
    # L'historique (paliers, montants) n'est pas supprime, seulement masque.
    assert bounty_program.reward_range() is None
    assert bounty_program.reward_policy.tiers.exists()


def test_ensure_reward_policy_consistency_is_idempotent(bounty_program):
    """Appeler la reconciliation plusieurs fois de suite ne doit ni dupliquer
    ni casser la politique existante."""
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.ensure_reward_policy_consistency()
    assert bounty_program.reward_policy.is_active is True

    bounty_program.program_type = ProgramType.VDP
    bounty_program.save(update_fields=["program_type"])
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is False

    bounty_program.program_type = ProgramType.BUG_BOUNTY
    bounty_program.save(update_fields=["program_type"])
    bounty_program.ensure_reward_policy_consistency()
    bounty_program.reward_policy.refresh_from_db()
    assert bounty_program.reward_policy.is_active is True


def test_reward_policy_cannot_attach_to_vdp_program(vdp_program):
    from django.core.exceptions import ValidationError

    from apps.programs.models import RewardPolicy

    policy = RewardPolicy(program=vdp_program)
    with pytest.raises(ValidationError):
        policy.full_clean()


# -------------------------------------------------------------------- creation
def test_program_create_view_reachable(client_for, coordinator):
    client = client_for(coordinator)
    assert client.get(reverse("programs:create")).status_code == 200


def test_create_bounty_program_gets_reward_policy_immediately(
    client_for, coordinator, organization, sla_policy
):
    client = client_for(coordinator)
    response = client.post(
        reverse("programs:create"),
        {
            "name": "Nouveau programme Bounty",
            "program_type": ProgramType.BUG_BOUNTY,
            "organization": organization.pk,
            "status": "DRAFT",
            "confidentiality": "PUBLIC",
            "disclosure_delay_days": 90,
            "sla_policy": sla_policy.pk,
        },
    )
    assert response.status_code == 302
    program = Program.objects.get(name="Nouveau programme Bounty")
    assert program.reward_policy is not None
    assert program.reward_policy.is_active is True
    # Un palier par severite est pre-cree pour eviter d'avoir a les ajouter
    # un par un avant de pouvoir simplement saisir les montants.
    assert program.reward_policy.tiers.count() == 5


def test_unfilled_default_tiers_are_not_shown_as_a_public_reward(
    client, coordinator, organization, sla_policy
):
    """Regression : les paliers 0/0 pre-crees a la creation ne doivent pas
    s'afficher comme si le programme offrait explicitement une recompense
    nulle, ni sur la fiche publique, ni via reward_range()."""
    program = Program.objects.create(
        name="Bounty tout neuf",
        program_type=ProgramType.BUG_BOUNTY,
        organization=organization,
        status="ACTIVE",
        confidentiality="PUBLIC",
        sla_policy=sla_policy,
    )
    program.ensure_reward_policy_consistency()
    assert program.reward_range() is None

    response = client.get(reverse("programs:detail", args=[program.slug]))
    assert response.status_code == 200
    assert "0 – 0" not in response.content.decode()


# ----------------------------------------------- statistiques et hall of fame
def test_program_detail_shows_trust_stats(client, bounty_case, coordinator):
    from apps.coordination.services import transition_case
    from apps.coordination.workflow import CaseStatus

    transition_case(bounty_case, CaseStatus.RECEIVED, actor=coordinator)

    response = client.get(reverse("programs:detail", args=[bounty_case.program.slug]))
    assert response.status_code == 200
    assert response.context["stats"]["total_reports"] == 1


def test_program_detail_hall_of_fame_lists_credited_researchers_only(
    client, bounty_case, coordinator
):
    """Seuls les chercheurs ayant choisi d'etre credites publiquement (et
    jamais "Chercheur anonyme") apparaissent sur la fiche du programme."""
    from apps.disclosures.services import create_advisory_from_case, publish_advisory

    advisory = create_advisory_from_case(bounty_case, coordinator, summary="Resume public.")
    advisory.status = "APPROVED"
    advisory.save(update_fields=["status"])
    publish_advisory(advisory, coordinator)

    response = client.get(reverse("programs:detail", args=[bounty_case.program.slug]))
    assert "bb-hunter" in response.context["hall_of_fame"]
    assert "Chercheur anonyme" not in response.context["hall_of_fame"]
    assert "bb-hunter" in response.content.decode()
