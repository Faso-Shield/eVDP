"""Vues publiques et de gestion des programmes VDP / Bug Bounty."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Avg, DurationField, ExpressionWrapper, F
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from apps.accounts.permissions import require_capability, require_not_read_only
from apps.accounts.roles import Capability
from apps.audit.models import AuditAction
from apps.audit.services import log_action
from apps.coordination.models import Case
from apps.coordination.workflow import CaseStatus
from apps.disclosures.models import Advisory, AdvisoryStatus

from .forms import ProgramForm, ProgramScopeForm, RewardTierFormSet
from .models import Program, ProgramType, RewardPolicy

#: Etats attestant qu'un dossier a au moins ete corrige (pas seulement soumis).
_RESOLVED_STATUSES = [
    CaseStatus.FIX_VERIFIED,
    CaseStatus.DISCLOSURE_SCHEDULED,
    CaseStatus.PUBLISHED,
    CaseStatus.CLOSED,
]


def _program_stats(program):
    """Indicateurs de confiance affiches publiquement sur la fiche programme.

    Calcules a la volee (pas de table de cache) : le volume par programme
    reste faible, la fraicheur importe plus que la performance ici.
    """
    cases = Case.objects.filter(program=program)
    avg_response = cases.filter(acknowledged_at__isnull=False).aggregate(
        avg=Avg(
            ExpressionWrapper(
                F("acknowledged_at") - F("created_at"), output_field=DurationField()
            )
        )
    )["avg"]
    rewards_paid = None
    if program.is_bug_bounty:
        policy = getattr(program, "reward_policy", None)
        if policy is not None:
            rewards_paid = policy.budget_consumed()
    return {
        "total_reports": cases.count(),
        "resolved_count": cases.filter(status__in=_RESOLVED_STATUSES).count(),
        "avg_response_hours": round(avg_response.total_seconds() / 3600, 1)
        if avg_response
        else None,
        "rewards_paid": rewards_paid,
    }


def _hall_of_fame(program, limit=12):
    """Chercheurs credites publiquement sur des advisories de ce programme.

    Reutilise Advisory.credit, deja calcule au moment de la publication en
    respectant le choix d'anonymat du declarant (voir credit_for()) : aucune
    identite non consentie n'est jamais exposee ici.
    """
    credits = (
        Advisory.objects.filter(status=AdvisoryStatus.PUBLISHED, case__program=program)
        .exclude(credit="")
        .exclude(credit__iexact="Chercheur anonyme")
        .order_by("-published_at")
        .values_list("credit", flat=True)
    )
    seen = []
    for name in credits:
        if name not in seen:
            seen.append(name)
        if len(seen) >= limit:
            break
    return seen


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
    reward_tiers = []
    if reward_policy and reward_policy.is_active:
        # Un palier a 0/0 est un emplacement pas encore rempli (voir
        # ensure_reward_policy_consistency) : ne jamais l'afficher comme si
        # le programme offrait explicitement une recompense nulle.
        reward_tiers = reward_policy.tiers.exclude(min_amount=0, max_amount=0)
    return render(
        request,
        "programs/detail.html",
        {
            "program": program,
            "in_scope": program.in_scope_targets(),
            "out_of_scope": program.out_of_scope_targets(),
            "rules": program.rule_items.all(),
            "reward_policy": reward_policy,
            "reward_tiers": reward_tiers,
            "can_manage": _can_manage(request.user, program),
            "stats": _program_stats(program),
            "hall_of_fame": _hall_of_fame(program),
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
            program.ensure_reward_policy_consistency()
            log_action(
                AuditAction.PROGRAM_CREATED,
                actor=request.user,
                obj=program,
                request=request,
                program_type=program.program_type,
            )
            messages.success(request, "Programme créé.")
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

    if request.method == "POST":
        form = ProgramForm(request.POST, instance=program, user=request.user)
        scope_form = ProgramScopeForm()
        # La politique affichee correspond au program_type AVANT cette
        # soumission : c'est celle sur laquelle porte le formset envoye.
        # Si le type change dans cette meme requete, ensure_reward_policy_
        # consistency() cree/desactive la politique APRES la sauvegarde, une
        # fois program_type reellement a jour en base.
        policy = getattr(program, "reward_policy", None)
        tier_formset = RewardTierFormSet(request.POST, instance=policy) if policy else None
        if form.is_valid() and (tier_formset is None or tier_formset.is_valid()):
            form.save()
            if tier_formset is not None:
                tier_formset.save()
            program.ensure_reward_policy_consistency()
            log_action(
                AuditAction.PROGRAM_UPDATED,
                actor=request.user,
                obj=program,
                request=request,
            )
            messages.success(request, "Programme mis à jour.")
            return redirect("programs:manage", slug=program.slug)
    else:
        policy = None
        if program.program_type == ProgramType.BUG_BOUNTY:
            policy, _ = RewardPolicy.objects.get_or_create(program=program)
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
        messages.success(request, "Périmètre ajouté.")
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
        messages.success(request, "Périmètre retiré.")
    return redirect("programs:manage", slug=program.slug)
