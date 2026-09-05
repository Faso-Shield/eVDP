from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("disclosure-policy/", views.disclosure_policy, name="disclosure_policy"),
    path("pgp-key.asc", views.pgp_key, name="pgp_key"),
    path(".well-known/security.txt", views.security_txt, name="security_txt"),
]
