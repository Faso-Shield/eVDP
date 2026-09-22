from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("", views.organization_list, name="list"),
    path("manage/", views.organization_manage_list, name="manage_list"),
    path("manage/new/", views.organization_create, name="create"),
    path("manage/<slug:slug>/", views.organization_manage, name="manage"),
    path(
        "manage/<slug:slug>/members/add/",
        views.organization_member_add,
        name="member_add",
    ),
    path("<slug:slug>/", views.organization_detail, name="detail"),
]
