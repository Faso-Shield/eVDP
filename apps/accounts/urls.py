from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.EvdpLoginView.as_view(), name="login"),
    path("login/verify/", views.mfa_verify, name="mfa_verify"),
    path("logout/", views.EvdpLogoutView.as_view(), name="logout"),
    path("register/", views.register, name="register"),
    path("verify-email/<str:token>/", views.verify_email, name="verify_email"),
    path("resend-verification/", views.resend_verification, name="resend_verification"),
    path("profile/", views.profile, name="profile"),
    path("profile/password/", views.change_password, name="change_password"),
    path("profile/mfa/activate/", views.mfa_activate, name="mfa_activate"),
    path("profile/mfa/disable/", views.mfa_disable, name="mfa_disable"),
    path("profile/api-keys/create/", views.api_key_create, name="api_key_create"),
    path(
        "profile/api-keys/<uuid:key_id>/revoke/", views.api_key_revoke, name="api_key_revoke"
    ),
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
    path("users/", views.user_manage_list, name="user_manage_list"),
    path("users/new/", views.user_manage_create, name="user_manage_create"),
    path("users/<uuid:user_id>/", views.user_manage_detail, name="user_manage_detail"),
    path(
        "users/<uuid:user_id>/resend-link/",
        views.user_manage_resend_link,
        name="user_manage_resend_link",
    ),
]
