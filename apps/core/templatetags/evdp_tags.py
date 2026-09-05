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
