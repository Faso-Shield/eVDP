"""Re-signe les messages existants dont le hash est obsolete (SHA-256 sans cle).

Correctif M1 du rapport de contre-test : apres activation de
MESSAGE_INTEGRITY_KEY, les anciens messages ont un hash SHA-256 non keye.
Cette commande verifie d'abord l'ancien hash, et si conforme, recalcule
le HMAC. Les messages reellement falsifies sont signales et laisses tels quels.

Usage :
    python manage.py resigner_messages
    python manage.py resigner_messages --dry-run

Idempotente : peut etre relancee sans risque.
"""

import hashlib
import logging

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.coordination.models import CaseMessage
from apps.core.utils import message_mac

logger = logging.getLogger("evdp.security")


def _legacy_hash(message):
    """Hash SHA-256 non keye (ancien mode degrade sans MESSAGE_INTEGRITY_KEY)."""
    parts = (
        message.pk,
        message.case_id,
        message.author_id,
        message.confidentiality,
        message.is_system,
        message.created_at.isoformat() if message.created_at else "",
        message.body,
    )
    return hashlib.sha256(str(parts).encode("utf-8")).hexdigest()


class Command(BaseCommand):
    help = "Re-signe les messages dont le hash SHA-256 est obsolete en HMAC-SHA256."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Affiche ce qui serait fait sans modifier la base.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        messages = CaseMessage.objects.all()
        total = messages.count()
        resigned = 0
        already_ok = 0
        tampered = 0

        for msg in messages.iterator():
            new_mac = message_mac(
                msg.pk,
                msg.case_id,
                msg.author_id,
                msg.confidentiality,
                msg.is_system,
                msg.created_at.isoformat() if msg.created_at else "",
                msg.body,
            )
            if msg.content_hash == new_mac:
                already_ok += 1
                continue

            legacy = _legacy_hash(msg)
            if msg.content_hash == legacy:
                if not dry_run:
                    msg.content_hash = new_mac
                    msg.save(update_fields=["content_hash", "updated_at"])
                resigned += 1
                self.stdout.write(f"  Re-signe : {msg.case.case_id} / message {msg.pk}")
            else:
                tampered += 1
                logger.warning(
                    "message_integrity_tampered",
                    extra={"message_id": str(msg.pk), "case_id": str(msg.case_id)},
                )
                self.stdout.write(
                    self.style.ERROR(
                        f"  ALTERE : {msg.case.case_id} / message {msg.pk} — hash inconnu"
                    )
                )

        prefix = "[DRY RUN] " if dry_run else ""
        self.stdout.write(
            self.style.SUCCESS(
                f"\n{prefix}{total} messages examines : "
                f"{already_ok} deja OK, {resigned} re-signes, {tampered} alteres."
            )
        )
