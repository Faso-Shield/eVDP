from django.urls import path

from . import views

app_name = "bounty"

urlpatterns = [
    path("", views.bounty_list, name="list"),
    path("case/<str:case_id>/propose/", views.propose, name="propose"),
    path("<uuid:bounty_id>/", views.bounty_detail, name="detail"),
    path("<uuid:bounty_id>/review/", views.review, name="review"),
    path("<uuid:bounty_id>/approve/", views.approve, name="approve"),
    path("<uuid:bounty_id>/reject/", views.reject, name="reject"),
    path("<uuid:bounty_id>/payment/", views.payment, name="payment"),
]
