"""Rendu Markdown assaini.

Tous les champs libres (description, impact, PoC, messages, politiques) sont
saisis en Markdown. Le rendu HTML est systematiquement passe par bleach :
aucun HTML fourni par un utilisateur ne doit atteindre le navigateur brut.
"""

import bleach
import markdown as md
from django.utils.safestring import mark_safe

ALLOWED_TAGS = [
    "p",
    "br",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "a",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "del",
    "sup",
    "sub",
]
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "rel", "target"],
    "code": ["class"],
    "pre": ["class"],
    "th": ["align"],
    "td": ["align"],
}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_markdown(text):
    """Convertit du Markdown en HTML sur pour l'affichage."""
    if not text:
        # Chaine vide : aucun contenu utilisateur.
        return mark_safe("")  # noqa: S308  # nosec
    html = md.markdown(
        text,
        extensions=["fenced_code", "tables", "nl2br", "sane_lists"],
        output_format="html",
    )
    cleaned = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    # Les liens externes ne doivent pas fuiter le referer ni ouvrir opener.
    cleaned = bleach.linkify(
        cleaned, callbacks=[_set_link_attributes], skip_tags=["pre", "code"]
    )
    # mark_safe est sur ici : `cleaned` sort de bleach.clean() avec une
    # liste blanche stricte de balises, d'attributs et de protocoles.
    return mark_safe(cleaned)  # noqa: S308  # nosec


def _set_link_attributes(attrs, new=False):
    attrs[(None, "rel")] = "noopener noreferrer nofollow"
    attrs[(None, "target")] = "_blank"
    return attrs


def strip_markdown(text, limit=None):
    """Version texte brut, utilisee pour les extraits et les exports."""
    if not text:
        return ""
    html = md.markdown(text, output_format="html")
    plain = bleach.clean(html, tags=[], attributes={}, strip=True)
    plain = " ".join(plain.split())
    if limit and len(plain) > limit:
        plain = plain[: limit - 1].rstrip() + "…"
    return plain
