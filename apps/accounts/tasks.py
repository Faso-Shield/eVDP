"""Taches de maintenance des comptes."""

from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from .models import UserToken


@shared_task(name="apps.accounts.tasks.purge_expired_tokens")
def purge_expired_tokens():
    """Supprime les jetons expires ou consommes depuis plus de 30 jours."""
    cutoff = timezone.now() - timedelta(days=30)
    expired = UserToken.objects.filter(expires_at__lt=timezone.now())
    consumed = UserToken.objects.filter(used_at__lt=cutoff)
    count = expired.count() + consumed.count()
    expired.delete()
    consumed.delete()
    return count


@shared_task(name="apps.accounts.tasks.remind_unverified_accounts")
def remind_unverified_accounts():
    """Relance les comptes non verifies avant l'expiration de leur sursis.

    Ne concerne que les comptes anterieurs a l'entree en vigueur de la regle :
    eux seuls disposent d'un sursis, et c'est a eux qu'il faut laisser une
    chance de se mettre en conformite avant de perdre l'acces aux Bug Bounty.

    Chaque jalon ne declenche qu'un envoi : la tache est idempotente si elle
    est rejouee dans la journee.
    """
    from apps.notifications.models import NotificationKind
    from apps.notifications.services import notify

    from .models import TokenPurpose, User, UserToken
    from .verification import grace_deadline, reminder_days

    aujourd_hui = timezone.localdate()
    jalons = reminder_days()
    envoyees = 0

    for user in User.objects.filter(is_active=True, email_verified=False):
        echeance = grace_deadline(user)
        if echeance is None:
            continue
        restant = (echeance - aujourd_hui).days
        if restant not in jalons or user.verification_reminded_on == aujourd_hui:
            continue

        token = UserToken.issue(user, TokenPurpose.EMAIL_VERIFICATION)
        jour = "jour" if restant <= 1 else "jours"
        notify(
            user,
            NotificationKind.ACCOUNT,
            title="Vérifiez votre adresse email pour continuer à participer",
            body=(
                f"Il vous reste {restant} {jour} pour vérifier votre adresse. "
                "Passe ce délai, vous ne pourrez plus signaler sur les "
                "programmes Bug Bounty."
            ),
            url=f"/verify-email/{token.token}/",
        )
        user.verification_reminded_on = aujourd_hui
        user.save(update_fields=["verification_reminded_on", "updated_at"])
        envoyees += 1

    return envoyees
