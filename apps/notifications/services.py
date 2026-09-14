"""Service de notification (in-app + email).

Regle de confidentialite : le corps des emails ne contient jamais de detail
technique, de PoC ni de titre de vulnerabilite complet. Il annonce seulement
qu'une action est disponible dans l'espace authentifie.
"""

import logging

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone

from .models import EmailTemplate, Notification, NotificationKind

logger = logging.getLogger("evdp.notifications")

#: Modeles par defaut, surchargeables via EmailTemplate en base.
DEFAULT_TEMPLATES = {
    NotificationKind.REPORT_RECEIVED: (
        "[eVDP] Nouveau signalement recu",
        "Un nouveau signalement à été enregistré sur la plateforme eVDP "
        "sous la référence {case_id}.\n\n"
        "Connectez-vous à votre espace securise pour le consulter :\n{link}",
    ),
    NotificationKind.ACKNOWLEDGEMENT: (
        "[eVDP] Accusé de réception de votre signalement",
        "Votre signalement a bien été reçu et enregistre sous la référence "
        "{case_id}.\n\nSuivez son traitement dans votre espace eVDP :\n{link}",
    ),
    NotificationKind.STATUS_CHANGED: (
        "[eVDP] Mise à jour du dossier {case_id}",
        "Le statut du dossier {case_id} a évolué.\n\n"
        "Consultez le détail dans votre espace securise :\n{link}",
    ),
    NotificationKind.NEW_MESSAGE: (
        "[eVDP] Nouveau message securise",
        "Un nouveau message securise est disponible dans votre espace eVDP "
        "pour le dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.NEW_ATTACHMENT: (
        "[eVDP] Nouvelle piece jointe",
        "Une nouvelle pièce jointe a été ajoutée au dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.INFORMATION_REQUESTED: (
        "[eVDP] Informations complementaires demandees",
        "L'équipe de coordination demande des informations complémentaires "
        "concernant le dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.CASE_ASSIGNED: (
        "[eVDP] Dossier assigne",
        "Le dossier {case_id} vous à été assigné.\n\n{link}",
    ),
    NotificationKind.VALIDATED: (
        "[eVDP] Signalement valide",
        "Votre signalement {case_id} à été validé par l'équipe de " "coordination.\n\n{link}",
    ),
    NotificationKind.REJECTED: (
        "[eVDP] Signalement non retenu",
        "Votre signalement {case_id} n'a pas été retenu. Le motif est "
        "consultable dans votre espace eVDP.\n\n{link}",
    ),
    NotificationKind.DUPLICATE: (
        "[eVDP] Signalement identifie comme doublon",
        "Votre rapport a été identifié comme doublon d'un signalement déjà "
        "enregistre (dossier {case_id}).\n\n{link}",
    ),
    NotificationKind.SLA_APPROACHING: (
        "[eVDP] Échéance proche sur le dossier {case_id}",
        "Une échéance de traitement approche pour le dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.SLA_BREACHED: (
        "[eVDP] Échéance dépassée sur le dossier {case_id}",
        "Une échéance de traitement est dépassée pour le dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.DISCLOSURE_UPCOMING: (
        "[eVDP] Divulgation planifiee",
        "La divulgation coordonnée du dossier {case_id} approche.\n\n{link}",
    ),
    NotificationKind.ADVISORY_PUBLISHED: (
        "[eVDP] Advisory publie",
        "Un advisory à été publié sur la plateforme eVDP.\n\n{link}",
    ),
    NotificationKind.BOUNTY_PROPOSED: (
        "[eVDP] Recompense proposee",
        "Une récompense a été proposée pour le dossier {case_id}.\n\n{link}",
    ),
    NotificationKind.BOUNTY_APPROVED: (
        "[eVDP] Recompense approuvee",
        "Une récompense a été approuvée pour votre signalement {case_id}. "
        "Le détail est disponible dans votre espace eVDP.\n\n{link}",
    ),
    NotificationKind.BOUNTY_REJECTED: (
        "[eVDP] Décision sur votre récompense",
        "Une décision a été rendue concernant la récompense du dossier "
        "{case_id}.\n\n{link}",
    ),
    NotificationKind.BOUNTY_PAID: (
        "[eVDP] Recompense versee",
        "Le versement de la récompense du dossier {case_id} a été " "enregistre.\n\n{link}",
    ),
    NotificationKind.ACCOUNT: (
        "[eVDP] Notification de compte",
        "Une action concernant votre compte eVDP requiert votre " "attention.\n\n{link}",
    ),
}


def _resolve_template(kind):
    override = EmailTemplate.objects.filter(code=kind, is_active=True).first()
    if override:
        return override.subject, override.body
    return DEFAULT_TEMPLATES.get(
        kind, ("[eVDP] Notification", "Une notification est disponible.\n\n{link}")
    )


def _absolute(path):
    base = (getattr(settings, "SITE_BASE_URL", "") or "").rstrip("/")
    if not base:
        hosts = [h for h in settings.ALLOWED_HOSTS if h not in ("*",)]
        host = hosts[0] if hosts else "localhost"
        scheme = "https" if not settings.DEBUG else "http"
        base = f"{scheme}://{host}"
    return f"{base}{path}"


def notify(recipient, kind, case=None, title=None, body=None, url=None, send_email=True):
    """Cree une notification interne et envoie l'email d'avis correspondant."""
    if recipient is None or not getattr(recipient, "is_active", False):
        return None

    subject_tpl, body_tpl = _resolve_template(kind)
    context = {
        "case_id": case.case_id if case else "",
        "title": (case.title if case else "") or "",
        "status": case.get_status_display() if case else "",
        "link": _absolute(url or (case.get_absolute_url() if case else "/dashboard/")),
    }

    notification = Notification.objects.create(
        recipient=recipient,
        kind=kind,
        title=(title or subject_tpl.format(**context))[:200],
        body=(body or "")[:400],
        url=url or (case.get_absolute_url() if case else ""),
        case=case,
    )

    if send_email and recipient.email:
        _send_email(recipient.email, subject_tpl, body_tpl, context, notification)
    return notification


def notify_external(email, kind, case=None, url=None):
    """Avis email pour un declarant sans compte (signalement anonyme)."""
    if not email:
        return
    subject_tpl, body_tpl = _resolve_template(kind)
    context = {
        "case_id": case.case_id if case else "",
        "title": "",
        "status": case.get_status_display() if case else "",
        "link": _absolute(url or "/"),
    }
    _send_email(email, subject_tpl, body_tpl, context, None)


def _send_email(email, subject_tpl, body_tpl, context, notification):
    try:
        send_mail(
            subject=subject_tpl.format(**context),
            message=body_tpl.format(**context),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        if notification is not None:
            notification.emailed_at = timezone.now()
            notification.save(update_fields=["emailed_at", "updated_at"])
    except Exception:
        logger.warning(
            "email_delivery_failed", extra={"recipient_domain": email.split("@")[-1]}
        )


def notify_many(recipients, kind, **kwargs):
    seen = set()
    created = []
    for recipient in recipients:
        if recipient is None or recipient.pk in seen:
            continue
        seen.add(recipient.pk)
        result = notify(recipient, kind, **kwargs)
        if result:
            created.append(result)
    return created


def notify_case_team(case, kind, exclude=None, **kwargs):
    """Notifie les participants actifs d'un case, hors auteur de l'action."""
    from apps.accounts.models import User

    participant_ids = set(case.participant_user_ids())
    if case.assignee_id:
        participant_ids.add(case.assignee_id)
    if case.reporter_id:
        participant_ids.add(case.reporter_id)
    if exclude is not None and getattr(exclude, "pk", None):
        participant_ids.discard(exclude.pk)
    recipients = User.objects.filter(id__in=participant_ids, is_active=True)
    return notify_many(recipients, kind, case=case, **kwargs)


def dashboard_url():
    return reverse("dashboard:home")
