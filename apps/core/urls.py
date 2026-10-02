from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("disclosure-policy/", views.disclosure_policy, name="disclosure_policy"),
    path("pgp-key.asc", views.pgp_key, name="pgp_key"),
    path("pgp/cle-nationale/", views.pgp_key_manage, name="pgp_key_manage"),
    path("pgp/cle-nationale/remises/", views.pgp_delivery_create, name="pgp_delivery_create"),
    path(
        "pgp/cle-nationale/remises/<uuid:delivery_id>/annuler/",
        views.pgp_delivery_revoke,
        name="pgp_delivery_revoke",
    ),
    path(
        "pgp/remise/<uuid:delivery_id>/",
        views.pgp_delivery_retrieve,
        name="pgp_delivery_retrieve",
    ),
    path(
        "pgp/remise/<uuid:delivery_id>/recuperer/",
        views.pgp_delivery_fetch,
        name="pgp_delivery_fetch",
    ),
    path(
        "pgp/remise/<uuid:delivery_id>/confirmer/",
        views.pgp_delivery_confirm,
        name="pgp_delivery_confirm",
    ),
    path(".well-known/security.txt", views.security_txt, name="security_txt"),
]
