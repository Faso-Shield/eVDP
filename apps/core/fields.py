"""Champs de modele chiffres au repos (Fernet).

Le masquage a l'affichage (apps.core.utils.mask_value) protege l'ecran, pas
la base : un dump SQL, une sauvegarde ou un acces direct au disque exposaient
sinon la valeur en clair. Ces champs chiffrent juste avant l'ecriture et
dechiffrent juste apres la lecture : formulaires, proprietes et gabarits
continuent de manipuler du texte en clair en memoire.

Cles : settings.FIELD_ENCRYPTION_KEYS. La premiere chiffre, toutes
dechiffrent : on ajoute une nouvelle cle en tete pour la rotation, puis
`python manage.py rechiffrer_champs` reecrit les valeurs avec elle avant de
retirer l'ancienne.

Le chiffre etant aleatoire, ces champs ne se filtrent ni ne se recherchent
en base : ne jamais les mettre dans un filter(), un search_fields ou un
index.
"""

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django import forms
from django.conf import settings
from django.core import validators
from django.core.exceptions import ImproperlyConfigured
from django.db import models

#: Tout jeton Fernet commence ainsi (octet de version 0x80 encode en base64).
#: Une valeur sans ce prefixe est une donnee anterieure au chiffrement.
FERNET_PREFIX = "gAAAAA"


@lru_cache(maxsize=4)
def _cipher(keys):
    return MultiFernet([Fernet(key) for key in keys])


def cipher():
    keys = tuple(getattr(settings, "FIELD_ENCRYPTION_KEYS", ()) or ())
    if not keys:
        raise ImproperlyConfigured(
            "FIELD_ENCRYPTION_KEYS est vide : aucune cle de chiffrement."
        )
    return _cipher(keys)


def encrypt(value):
    return cipher().encrypt(value.encode()).decode()


def decrypt(value):
    """Dechiffre `value`, ou la rend telle quelle si elle est encore en clair.

    Un jeton qu'aucune cle n'ouvre ne doit pas passer pour du texte : ce
    serait afficher du chiffre comme une donnee valide, puis le rechiffrer
    au prochain enregistrement et perdre la valeur pour de bon.
    """
    if not value.startswith(FERNET_PREFIX):
        return value
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ImproperlyConfigured(
            "Valeur chiffree illisible avec FIELD_ENCRYPTION_KEYS : cle absente ou erronee."
        ) from exc


def encrypted_field_names(model):
    return [f.name for f in model._meta.concrete_fields if isinstance(f, EncryptedTextField)]


def rewrite_encrypted_fields(model):
    """Reecrit chaque valeur chiffree avec la premiere cle.

    Sert a chiffrer les donnees anterieures au chiffrement (lues en clair) et
    a la rotation de cle. Passe par update() : ni save() ni signaux.
    """
    names = encrypted_field_names(model)
    count = 0
    for row in model.objects.values("pk", *names).iterator():
        values = {name: row[name] for name in names if row[name]}
        if values:
            model.objects.filter(pk=row["pk"]).update(**values)
            count += 1
    return count


class EncryptedTextField(models.TextField):
    """Texte chiffre. La colonne est toujours TEXT : le chiffre est plus long
    que la valeur d'origine, un VARCHAR(N) le tronquerait."""

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        return decrypt(value)

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if not value:
            return value
        return encrypt(value)


class EncryptedCharField(EncryptedTextField):
    """Chaine courte chiffree : longueur maximale validee par le formulaire et
    `full_clean()`, colonne TEXT en base (voir EncryptedTextField)."""

    def __init__(self, *args, max_length=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Apres super() : Field.__init__ remettrait max_length a None.
        self.max_length = max_length
        if max_length is not None:
            self.validators.append(validators.MaxLengthValidator(max_length))

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.max_length is not None:
            kwargs["max_length"] = self.max_length
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        # Sans widget explicite, TextField impose un <textarea>.
        defaults = {"max_length": self.max_length, "widget": forms.TextInput}
        defaults.update(kwargs)
        return super().formfield(**defaults)


class EncryptedEmailField(EncryptedCharField):
    default_validators = [validators.validate_email]

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.EmailField, "widget": forms.EmailInput}
        defaults.update(kwargs)
        return super().formfield(**defaults)
