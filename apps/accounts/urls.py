from django.urls import path

from . import views, views_manage

app_name = "accounts"

urlpatterns = [
    path("login/", views.EvdpLoginView.as_view(), name="login"),
    path("logout/", views.EvdpLogoutView.as_view(), name="logout"),
    path("register/", views.register, name="register"),
    path("mfa/", views.mfa_challenge, name="mfa_challenge"),
    path("mfa/enrolement/", views.mfa_setup, name="mfa_setup"),
    path("mfa/codes-de-secours/", views.mfa_backup_codes, name="mfa_backup_codes"),
    path(
        "mfa/codes-de-secours/regenerer/",
        views.mfa_regenerate_backup_codes,
        name="mfa_regenerate_backup_codes",
    ),
    path("verify-email/<str:token>/", views.verify_email, name="verify_email"),
    path("resend-verification/", views.resend_verification, name="resend_verification"),
    path("activation/renvoyer/", views.resend_activation, name="resend_activation"),
    path("profile/", views.profile, name="profile"),
    path("profile/password/", views.change_password, name="change_password"),
    path("profile/api-keys/new/", views.api_key_create, name="api_key_create"),
    path("profile/api-keys/created/", views.api_key_created, name="api_key_created"),
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
    # Gestion des comptes (MANAGE_USERS), hors administration Django.
    path("comptes/", views_manage.user_manage_list, name="user_manage_list"),
    path("comptes/nouveau/", views_manage.user_manage_create, name="user_manage_create"),
    path("comptes/<uuid:pk>/", views_manage.user_manage_detail, name="user_manage_detail"),
    path(
        "comptes/<uuid:pk>/lien/",
        views_manage.user_manage_resend_link,
        name="user_manage_resend_link",
    ),
    path(
        "comptes/<uuid:pk>/mfa/",
        views_manage.user_manage_reset_mfa,
        name="user_manage_reset_mfa",
    ),
]
