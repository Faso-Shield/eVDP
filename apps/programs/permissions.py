"""Droit de gerer un programme donne, partage par la vue web et l'API."""

from apps.accounts.roles import Capability


def can_manage_program(user, program):
    """Vrai si `user` peut modifier ou supprimer `program`.

    La capacite MANAGE_PROGRAM ne suffit pas : hors rôle national, elle ne
    vaut que pour les programmes des organisations de l'utilisateur.
    """
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.has_capability(Capability.MANAGE_ALL_ORGANIZATIONS):
        return True
    if not user.has_capability(Capability.MANAGE_PROGRAM):
        return False
    if user.is_national:
        return True
    return program.organization_id in set(user.organization_ids())
