from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("report/", views.submit, name="submit"),
    path("report/<slug:slug>/", views.program_report, name="program_report"),
    path("suivi/", views.track_lookup, name="track_lookup"),
    path("suivi/<str:token>/", views.track_status, name="track_status"),
]
