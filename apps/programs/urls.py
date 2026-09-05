from django.urls import path

from . import views

app_name = "programs"

urlpatterns = [
    path("", views.program_list, name="list"),
    path("manage/", views.my_programs, name="my_programs"),
    path("manage/new/", views.program_create, name="create"),
    path("manage/<slug:slug>/", views.program_manage, name="manage"),
    path("manage/<slug:slug>/scopes/", views.scope_add, name="scope_add"),
    path(
        "manage/<slug:slug>/scopes/<uuid:scope_id>/delete/",
        views.scope_delete,
        name="scope_delete",
    ),
    path("<slug:slug>/", views.program_detail, name="detail"),
]
