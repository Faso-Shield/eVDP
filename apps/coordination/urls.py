from django.urls import path

from . import views

app_name = "coordination"

urlpatterns = [
    path("", views.case_list, name="case_list"),
    path("kanban/", views.kanban, name="kanban"),
    path("mine/", views.my_claimed_cases, name="my_claims"),
    path("<str:case_id>/", views.case_detail, name="case_detail"),
    path("<str:case_id>/messages/", views.post_case_message, name="post_message"),
    path(
        "<str:case_id>/actions/<slug:action_key>/",
        views.workflow_action,
        name="workflow_action",
    ),
    path("<str:case_id>/triage/", views.triage, name="triage"),
    path("<str:case_id>/claim/", views.claim, name="claim"),
    path("<str:case_id>/transfer/", views.transfer, name="transfer"),
    path("<str:case_id>/disclosure/", views.set_disclosure_date, name="set_disclosure"),
    path("<str:case_id>/cve/", views.link_cve, name="link_cve"),
    path("<str:case_id>/attachments/", views.upload_attachment, name="upload_attachment"),
]
