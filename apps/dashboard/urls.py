from django.urls import path

from . import exports, views

app_name = "dashboard"

urlpatterns = [
    path("", views.home, name="home"),
    path("researcher/", views.researcher_dashboard, name="researcher"),
    path("organization/", views.organization_dashboard, name="organization"),
    path("csirt/", views.csirt_dashboard, name="csirt"),
    path("national/", views.national_dashboard, name="national"),
    path("search/", views.search, name="search"),
    path("exports/cases.csv", exports.export_cases_csv, name="export_cases_csv"),
    path("exports/cases.xlsx", exports.export_cases_xlsx, name="export_cases_xlsx"),
    path(
        "exports/comptes-non-verifies.csv",
        exports.export_unverified_accounts_csv,
        name="export_unverified_accounts_csv",
    ),
    path("exports/case/<str:case_id>.pdf", exports.export_case_pdf, name="export_case_pdf"),
]
