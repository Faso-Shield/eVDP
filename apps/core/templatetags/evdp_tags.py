"""Filtres de gabarit eVDP."""

from django import template

from apps.core.markdown_utils import render_markdown, strip_markdown

register = template.Library()


@register.filter(name="markdown")
def markdown_filter(value):
    return render_markdown(value)


@register.filter(name="markdown_excerpt")
def markdown_excerpt(value, limit=180):
    return strip_markdown(value, int(limit))


@register.filter(name="severity_class")
def severity_class(value):
    return {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
        "INFO": "sev-info",
    }.get((value or "").upper(), "sev-info")


@register.filter(name="money")
def money(value):
    try:
        return f"{int(value):,}".replace(",", " ")
    except (TypeError, ValueError):
        return value


@register.filter(name="initials")
def initials(value):
    """Monogramme d'une organisation : acronyme, sinon initiales du nom.

    Sert de logo de substitution : la plateforme ne stocke aucune image
    d'organisation.
    """
    acronym = (getattr(value, "acronym", "") or "").strip()
    if acronym:
        return acronym[:4].upper()
    name = str(getattr(value, "name", value) or "").strip()
    words = [word for word in name.split() if len(word) > 2]
    if not words:
        return (name[:2] or "?").upper()
    return "".join(word[0] for word in words[:3]).upper()


@register.simple_tag(takes_context=True)
def query_replace(context, **kwargs):
    """Reconstruit la query string en remplacant certains parametres."""
    request = context["request"]
    params = request.GET.copy()
    for key, value in kwargs.items():
        if value in (None, ""):
            params.pop(key, None)
        else:
            params[key] = value
    return params.urlencode()


@register.simple_tag(takes_context=True)
def case_status(context, case):
    """Statut affiche : simplifie (5 paliers) pour le declarant du dossier.

    Le declarant ne voit jamais l'avancement interne (rejet seulement
    propose, qualification en attente de validation, etc.).
    """
    from apps.coordination.workflow import public_status_bucket

    user = context.get("user")
    if user is not None and getattr(user, "pk", None) and case.reporter_id == user.pk:
        return public_status_bucket(case.status)[1]
    return case.get_status_display()


@register.filter(name="sla_badge")
def sla_badge(case):
    """Badge d'echeance d'une carte Kanban : vert, orange a 75 %, rouge a echeance."""
    from apps.coordination.selectors import sla_color

    return sla_color(case)
