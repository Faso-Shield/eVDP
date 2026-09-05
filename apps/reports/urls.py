from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("report/", views.submit, name="submit"),
    path("report/<slug:slug>/", views.program_report, name="program_report"),
]
