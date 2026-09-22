"""Reinitialisation hors ligne de la double authentification d'un compte.

Recours de dernier ressort : l'action equivalente de l'administration Django
exige d'y etre connecte, donc d'avoir deja passe son propre second facteur.
Si le seul administrateur perd son appareil, plus personne ne peut le
depanner depuis l'interface. Cette commande demande un acces au serveur, ce
qui constitue la garantie a la place du second facteur.
"""

from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User
from apps.audit.models import AuditAction
from apps.audit.services import log_action


class Command(BaseCommand):
    help = "Revoque l'enrolement TOTP d'un compte, qui devra en refaire un."

    def add_arguments(self, parser):
        parser.add_argument("email", help="Adresse du compte a reinitialiser.")

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist as exc:
            raise CommandError(f"Aucun compte pour {email}.") from exc

        if not user.mfa_required:
            raise CommandError(
                f"{email} porte le role {user.role}, qui n'est pas soumis a la "
                "double authentification : il n'y a rien a reinitialiser."
            )
        if not (user.mfa_enabled or user.mfa_secret):
            self.stdout.write(f"{email} n'avait aucun authentificateur enregistre.")
            return

        user.reset_mfa()
        # Acteur volontairement absent : la commande s'execute hors session,
        # la tracabilite repose sur l'acces au serveur.
        log_action(AuditAction.MFA_RESET, obj=user, source="commande")
        self.stdout.write(
            self.style.SUCCESS(
                f"Enrolement revoque pour {email}. Sa prochaine connexion "
                "demandera l'enregistrement d'un nouvel authentificateur."
            )
        )
