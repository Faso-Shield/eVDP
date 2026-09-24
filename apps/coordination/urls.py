from django.urls import path

from . import views

app_name = "coordination"

urlpatterns = [
    path("", views.case_list, name="case_list"),
    path("kanban/", views.kanban, name="kanban"),
    path("<str:case_id>/", views.case_detail, name="case_detail"),
    path("<str:case_id>/messages/", views.post_case_message, name="post_message"),
    path("<str:case_id>/action/", views.workflow_action, name="workflow_action"),
    path("<str:case_id>/status/", views.change_status, name="change_status"),
    path("<str:case_id>/step/<slug:step>/", views.save_step, name="save_step"),
    path("<str:case_id>/escalate/", views.escalate, name="escalate"),
    path("<str:case_id>/triage/", views.triage, name="triage"),
    path("<str:case_id>/assign/", views.assign, name="assign"),
    path("<str:case_id>/duplicate/", views.mark_as_duplicate, name="mark_duplicate"),
    path("<str:case_id>/disclosure/", views.set_disclosure_date, name="set_disclosure"),
    path("<str:case_id>/cve/", views.link_cve, name="link_cve"),
    path("<str:case_id>/attachments/", views.upload_attachment, name="upload_attachment"),
]
