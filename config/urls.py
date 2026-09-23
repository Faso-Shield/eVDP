"""Routage racine eVDP."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from apps.core import views as core_views

admin.site.site_header = "Administration eVDP"
admin.site.site_title = "eVDP"
admin.site.index_title = "Plateforme nationale de divulgation coordonnee"

urlpatterns = [
    # Pages publiques institutionnelles
    path("", include("apps.core.urls")),
    path("", include("apps.accounts.urls")),
    path("", include("apps.reports.urls")),
    path("programs/", include("apps.programs.urls")),
    path("advisories/", include("apps.disclosures.urls")),
    path("organizations/", include("apps.organizations.urls")),
    path("researchers/", include("apps.researchers.urls")),
    # Espace authentifie
    path("dashboard/", include("apps.dashboard.urls")),
    path("wallet/", include("apps.researchers.wallet_urls")),
    path("cases/", include("apps.coordination.urls")),
    path("bounties/", include("apps.bounty.urls")),
    path("attachments/", include("apps.attachments.urls")),
    path("notifications/", include("apps.notifications.urls")),
    path("audit/", include("apps.audit.urls")),
    # API et observabilite
    path("api/", include("apps.api.urls")),
    path("health/", core_views.health, name="health"),
    path("ready/", core_views.ready, name="ready"),
    path("metrics/", core_views.metrics, name="metrics"),
    # Administration Django
    path("admin/", admin.site.urls),
]

handler400 = "apps.core.views.error_400"
handler403 = "apps.core.views.error_403"
handler404 = "apps.core.views.error_404"
handler500 = "apps.core.views.error_500"

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
