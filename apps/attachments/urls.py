from django.urls import path

from . import views

app_name = "attachments"

urlpatterns = [
    path("<uuid:attachment_id>/download/", views.download, name="download"),
]
