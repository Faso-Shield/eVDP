"""Validateurs de mots de passe supplementaires (OWASP ASVS V2.1.7)."""

import re
import string

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class UppercaseValidator:
    def validate(self, password, user=None):
        if not any(c in string.ascii_uppercase for c in password):
            raise ValidationError(
                _("Le mot de passe doit contenir au moins une lettre majuscule."),
                code="password_no_uppercase",
            )

    def get_help_text(self):
        return _("Votre mot de passe doit contenir au moins une lettre majuscule.")


class LowercaseValidator:
    def validate(self, password, user=None):
        if not any(c in string.ascii_lowercase for c in password):
            raise ValidationError(
                _("Le mot de passe doit contenir au moins une lettre minuscule."),
                code="password_no_lowercase",
            )

    def get_help_text(self):
        return _("Votre mot de passe doit contenir au moins une lettre minuscule.")


class SpecialCharacterValidator:
    def validate(self, password, user=None):
        if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
            raise ValidationError(
                _("Le mot de passe doit contenir au moins un caractere special."),
                code="password_no_special",
            )

    def get_help_text(self):
        return _("Votre mot de passe doit contenir au moins un caractere special.")


class DigitValidator:
    def validate(self, password, user=None):
        if not any(c.isdigit() for c in password):
            raise ValidationError(
                _("Le mot de passe doit contenir au moins un chiffre."),
                code="password_no_digit",
            )

    def get_help_text(self):
        return _("Votre mot de passe doit contenir au moins un chiffre.")
