from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.EvdpLoginView.as_view(), name="login"),
    path("logout/", views.EvdpLogoutView.as_view(), name="logout"),
    path("register/", views.register, name="register"),
    path("mfa/", views.mfa_challenge, name="mfa_challenge"),
    path("mfa/enrolement/", views.mfa_setup, name="mfa_setup"),
    path("verify-email/<str:token>/", views.verify_email, name="verify_email"),
    path("resend-verification/", views.resend_verification, name="resend_verification"),
    path("profile/", views.profile, name="profile"),
    path("profile/password/", views.change_password, name="change_password"),
    path("password-reset/", views.EvdpPasswordResetView.as_view(), name="password_reset"),
    path(
        "password-reset/done/",
        views.EvdpPasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        views.EvdpPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        views.EvdpPasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
]
