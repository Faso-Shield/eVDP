"""Routage de l'API v1."""

from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.routers import DefaultRouter

from apps.csaf.views import CsafImportView

from . import views

router = DefaultRouter()
router.register("reports", views.ReportViewSet, basename="report")
router.register("programs", views.ProgramViewSet, basename="program")
router.register("advisories", views.AdvisoryViewSet, basename="advisory")
router.register("organizations", views.OrganizationViewSet, basename="organization")
router.register("researchers", views.ResearcherViewSet, basename="researcher")
router.register("bounties", views.BountyViewSet, basename="bounty")
router.register("search", views.SearchView, basename="search")

app_name = "api"

urlpatterns = [
    path("v1/", include(router.urls)),
    path("v1/import/csaf/", CsafImportView.as_view(), name="csaf_import"),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "docs/",
        SpectacularSwaggerView.as_view(url_name="api:schema"),
        name="swagger",
    ),
    path(
        "redoc/",
        SpectacularRedocView.as_view(url_name="api:schema"),
        name="redoc",
    ),
]
