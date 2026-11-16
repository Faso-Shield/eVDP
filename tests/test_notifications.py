"""Tests des notifications : isolation, confidentialite des emails."""

import pytest
from django.core import mail
from django.urls import reverse

from apps.notifications.models import Notification, NotificationKind
from apps.notifications.services import notify, notify_external

pytestmark = pytest.mark.django_db


# -------------------------------------------------------------------- isolation
def test_user_cannot_mark_another_users_notification_as_read(
    client_for, researcher_a, researcher_b
):
    """Regression (couverture manquante) : mark_read() filtre deja par
    `recipient=request.user`, ce test verifie que ca tient reellement."""
    notification = notify(researcher_b, NotificationKind.ACCOUNT, title="Pour B", body="")
    client = client_for(researcher_a)
    response = client.get(reverse("notifications:mark_read", args=[notification.pk]))
    assert response.status_code == 404
    notification.refresh_from_db()
    assert notification.read_at is None


def test_user_can_mark_own_notification_as_read(client_for, researcher_a):
    notification = notify(researcher_a, NotificationKind.ACCOUNT, title="Pour moi", body="")
    client = client_for(researcher_a)
    client.get(reverse("notifications:mark_read", args=[notification.pk]))
    notification.refresh_from_db()
    assert notification.read_at is not None


def test_notification_list_only_shows_own_notifications(
    client_for, researcher_a, researcher_b
):
    notify(researcher_a, NotificationKind.ACCOUNT, title="Notification A", body="")
    notify(researcher_b, NotificationKind.ACCOUNT, title="Notification B", body="")
    client = client_for(researcher_a)
    content = client.get(reverse("notifications:list")).content.decode()
    assert "Notification A" in content
    assert "Notification B" not in content


def test_mark_all_read_does_not_affect_other_users(client_for, researcher_a, researcher_b):
    notif_a = notify(researcher_a, NotificationKind.ACCOUNT, title="A", body="")
    notif_b = notify(researcher_b, NotificationKind.ACCOUNT, title="B", body="")
    client = client_for(researcher_a)
    client.get(reverse("notifications:mark_all_read"))
    notif_a.refresh_from_db()
    notif_b.refresh_from_db()
    assert notif_a.read_at is not None
    assert notif_b.read_at is None


# --------------------------------------------------------- confidentialite email
def test_email_body_never_contains_case_title_or_technical_detail(researcher_a, case_alpha):
    """Regle affichee dans apps/notifications/services.py : le corps de
    l'email ne doit jamais contenir le titre du dossier ni un detail
    technique, seulement une reference et un lien vers l'espace securise."""
    case_alpha.title = "Injection SQL critique sur le module de paiement XYZ"
    case_alpha.save(update_fields=["title"])
    mail.outbox.clear()

    notify(researcher_a, NotificationKind.STATUS_CHANGED, case=case_alpha)

    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert case_alpha.title not in body
    assert case_alpha.case_id in body


def test_notify_external_email_also_excludes_case_title(case_alpha):
    case_alpha.title = "Details sensibles a ne jamais envoyer par email"
    case_alpha.save(update_fields=["title"])
    mail.outbox.clear()

    notify_external("declarant@exemple.bf", NotificationKind.ACKNOWLEDGEMENT, case=case_alpha)

    assert len(mail.outbox) == 1
    assert case_alpha.title not in mail.outbox[0].body


def test_notify_does_nothing_for_inactive_user(researcher_a):
    researcher_a.is_active = False
    researcher_a.save(update_fields=["is_active"])
    mail.outbox.clear()
    result = notify(researcher_a, NotificationKind.ACCOUNT, title="X", body="")
    assert result is None
    assert len(mail.outbox) == 0
    assert not Notification.objects.filter(recipient=researcher_a, title="X").exists()


# ------------------------------------------------------- echec d'envoi
def _delivery_failures(caplog):
    return [r for r in caplog.records if r.getMessage() == "email_delivery_failed"]


def test_failed_notification_logs_the_smtp_cause(caplog, monkeypatch, researcher_a):
    """La cause doit figurer au journal : sans elle, seul sendtestemail la montrait."""
    import smtplib

    def refuse(**kwargs):
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")

    monkeypatch.setattr("apps.notifications.services.send_mail", refuse)
    with caplog.at_level("WARNING", logger="evdp.notifications"):
        notify(researcher_a, NotificationKind.ACCOUNT, title="X", body="")

    [record] = _delivery_failures(caplog)
    assert record.error == "SMTPAuthenticationError"
    assert record.smtp_code == 535
    assert "not accepted" in record.smtp_reply
    assert record.purpose == "notification"


def test_refused_recipient_is_logged_without_the_address(caplog, monkeypatch, researcher_a):
    import smtplib

    def refuse(**kwargs):
        raise smtplib.SMTPRecipientsRefused({researcher_a.email: (550, b"5.1.1 unknown")})

    monkeypatch.setattr("apps.notifications.services.send_mail", refuse)
    with caplog.at_level("WARNING", logger="evdp.notifications"):
        notify(researcher_a, NotificationKind.ACCOUNT, title="X", body="")

    [record] = _delivery_failures(caplog)
    assert record.smtp_code == [550]
    assert researcher_a.email not in str(record.__dict__)


def test_failed_activation_email_is_logged_not_raised(caplog, monkeypatch, researcher_a):
    """Avant : fail_silently=True, un echec ne laissait aucune trace."""
    from apps.accounts.models import TokenPurpose, UserToken
    from apps.accounts.views import send_activation_email

    def timeout(**kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("django.core.mail.send_mail", timeout)
    token = UserToken.issue(researcher_a, TokenPurpose.EMAIL_VERIFICATION)
    with caplog.at_level("WARNING", logger="evdp.notifications"):
        send_activation_email(researcher_a, token)

    [record] = _delivery_failures(caplog)
    assert record.purpose == "activation"
    assert record.error == "TimeoutError"
    assert record.detail == "timed out"
