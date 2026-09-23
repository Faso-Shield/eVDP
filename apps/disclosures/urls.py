from django.urls import path

from . import views

app_name = "disclosures"

urlpatterns = [
    path("", views.advisory_list, name="advisory_list"),
    path("manage/", views.advisory_manage_list, name="manage_list"),
    path("manage/new/", views.advisory_create, name="create"),
    path("manage/from-case/<str:case_id>/", views.advisory_create, name="create_from_case"),
    path("manage/<str:advisory_id>/", views.advisory_manage, name="manage"),
    path("<str:advisory_id>/", views.advisory_detail, name="advisory_detail"),
]
