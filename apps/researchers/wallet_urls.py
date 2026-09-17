"""Routage du portefeuille de versement.

Module distinct de urls.py : celui-ci sert l'annuaire PUBLIC des chercheurs
(/researchers/), un espace totalement different de ce portefeuille prive,
en libre-service, mont sous /wallet/ (voir config/urls.py).
"""

from django.urls import path

from . import views

app_name = "wallet"

urlpatterns = [
    path("", views.wallet_home, name="home"),
    path("methods/add/", views.payout_method_add, name="method_add"),
    path("methods/<uuid:method_id>/edit/", views.payout_method_edit, name="method_edit"),
    path(
        "methods/<uuid:method_id>/set-primary/",
        views.payout_method_set_primary,
        name="method_set_primary",
    ),
    path(
        "methods/<uuid:method_id>/remove/",
        views.payout_method_remove,
        name="method_remove",
    ),
]
