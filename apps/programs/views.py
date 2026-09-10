"""Vues publiques et de gestion des programmes VDP / Bug Bounty."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action

from .forms import ProgramForm, ProgramScopeForm, RewardTierFormSet
from .models import Program, ProgramType, RewardPolicy


def program_list(request):
    """Annuaire public des programmes actifs."""
    queryset = Program.objects.public().select_related("organization")
    program_type = request.GET.get("type", "").upper()
    if program_type in ProgramType.values:
        queryset = queryset.filter(program_type=program_type)
    page = Paginator(queryset, 12).get_page(request.GET.get("page"))
    return render(
        request,
        "programs/list.html",
        {
            "page_obj": page,
            "program_type": program_type,
            "types": ProgramType.choices,
        },
    )


def program_detail(request, slug):
    """Fiche publique d'un programme (perimetre, regles, recompenses)."""
    program = get_object_or_404(Program.objects.select_related("organization"), slug=slug)
    if not program.is_public:
        # Un programme prive ou en brouillon n'est visible que de son perimetre.
        if not _can_manage(request.user, program):
            raise Http404("Programme introuvable.")
    reward_policy = getattr(program, "reward_policy", None)
    return render(
        request,
        "programs/detail.html",
        {
            "program": program,
            "in_scope": program.in_scope_targets().prefetch_related("reward_tiers"),
            "out_of_scope": program.out_of_scope_targets(),
            "rules": program.rule_items.all(),
            "reward_policy": reward_policy,
            # La grille par defaut et les grilles propres a un actif sont
            # presentees separement : melangees, on ne saurait plus quel
            # montant s'applique a quoi.
            "reward_tiers": (
                reward_policy.tiers.filter(scope__isnull=True) if reward_policy else []
            ),
            "reward_scopes": reward_policy.scopes_with_tiers() if reward_policy else [],
            "can_manage": _can_manage(request.user, program),
            # Annonce des l'arrivee sur la page si le visiteur ne remplit pas
            # les conditions, plutot que de le laisser rediger un rapport pour
            # se le voir refuser a l'envoi.
            "refus_participation": program.reporter_rejection(request.user),
        },
    )


def _can_manage(user, program):
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS):
        return True
    if not user.has_capability(Capability.MANAGE_PROGRAM):
        return False
    if user.is_national:
        return True
    return program.organization_id in set(user.organization_ids())


@login_required
def my_programs(request):
    """Programmes gerables par l'utilisateur."""
    if request.user.is_national:
        queryset = Program.objects.all()
    else:
        queryset = Program.objects.for_organizations(request.user.organization_ids())
    queryset = queryset.select_related("organization").order_by("-created_at")
    return render(request, "programs/manage_list.html", {"programs": queryset})


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_PROGRAM)
def program_create(request):
    if request.method == "POST":
        form = ProgramForm(request.POST, user=request.user)
        if form.is_valid():
            program = form.save(commit=False)
            program.created_by = request.user
            program.save()
            if program.program_type == ProgramType.BUG_BOUNTY:
                RewardPolicy.objects.get_or_create(program=program)
            log_action(
                AuditAction.PROGRAM_CREATED,
                actor=request.user,
                obj=program,
                request=request,
                program_type=program.program_type,
            )
            messages.success(request, "Programme cree.")
            return redirect("programs:manage", slug=program.slug)
    else:
        form = ProgramForm(user=request.user)
    return render(request, "programs/form.html", {"form": form, "creating": True})


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_PROGRAM)
def program_manage(request, slug):
    program = get_object_or_404(Program, slug=slug)
    if not _can_manage(request.user, program):
        raise Http404("Programme introuvable.")

    policy = None
    if program.program_type == ProgramType.BUG_BOUNTY:
        policy, _ = RewardPolicy.objects.get_or_create(program=program)

    if request.method == "POST":
        form = ProgramForm(request.POST, instance=program, user=request.user)
        scope_form = ProgramScopeForm()
        tier_formset = RewardTierFormSet(request.POST, instance=policy) if policy else None
        if form.is_valid() and (tier_formset is None or tier_formset.is_valid()):
            form.save()
            if tier_formset is not None:
                tier_formset.save()
            log_action(
                AuditAction.PROGRAM_UPDATED,
                actor=request.user,
                obj=program,
                request=request,
            )
            messages.success(request, "Programme mis a jour.")
            return redirect("programs:manage", slug=program.slug)
    else:
        form = ProgramForm(instance=program, user=request.user)
        scope_form = ProgramScopeForm()
        tier_formset = RewardTierFormSet(instance=policy) if policy else None

    return render(
        request,
        "programs/manage.html",
        {
            "program": program,
            "form": form,
            "scope_form": scope_form,
            "tier_formset": tier_formset,
            "scopes": program.scopes.all(),
            "reward_policy": policy,
        },
    )


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_PROGRAM)
def scope_add(request, slug):
    program = get_object_or_404(Program, slug=slug)
    if not _can_manage(request.user, program):
        raise Http404("Programme introuvable.")
    form = ProgramScopeForm(request.POST)
    if form.is_valid():
        scope = form.save(commit=False)
        scope.program = program
        scope.save()
        log_action(
            AuditAction.PROGRAM_UPDATED,
            actor=request.user,
            obj=program,
            request=request,
            scope_added=scope.identifier,
        )
        messages.success(request, "Perimetre ajoute.")
    else:
        messages.error(request, form.errors.as_text())
    return redirect("programs:manage", slug=program.slug)


@login_required
@require_not_read_only
@require_capability(Capability.MANAGE_PROGRAM)
def scope_delete(request, slug, scope_id):
    program = get_object_or_404(Program, slug=slug)
    if not _can_manage(request.user, program):
        raise Http404("Programme introuvable.")
    deleted, _ = program.scopes.filter(pk=scope_id).delete()
    if deleted:
        log_action(
            AuditAction.PROGRAM_UPDATED,
            actor=request.user,
            obj=program,
            request=request,
            scope_removed=str(scope_id),
        )
        messages.success(request, "Perimetre retire.")
    return redirect("programs:manage", slug=program.slug)
