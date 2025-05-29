from django.urls import path


from .views import (
    AccessCodeByUserListView, AccessCodeDeactivateView, AccessCodeRetrieveView, AccessCodeUnapprovedCountView, AccessCodeVerifiedCountView, AccessCodeVerifyView, AlertCreateView, AlertListView, LostFoundItemDetailView, SignupView, LoginView, UserUpdateView, VerifyAndCreditView, VerifyEmailView,
    ResendVerificationEmailView, GoogleSignInView,
    PasswordResetRequestView, PasswordResetConfirmView, DeleteAccountView,
    LogoutView, CheckEmailVerificationView, LoginWithIdView,
    AccessCodeCreateView, VisitorCheckinListView,VerifyAndCreditView,
    LostFoundItemCreateView, LostFoundItemListView,
)



urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/<int:pk>/', LoginWithIdView.as_view(), name='login-with-id'),
    path('user/<int:pk>/', UserUpdateView.as_view(), name='user-update'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    path('google-signin/', GoogleSignInView.as_view(), name='google-signin'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('delete-account/<int:pk>/', DeleteAccountView.as_view(), name='delete-account'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('check-email-verification/', CheckEmailVerificationView.as_view(), name='check-email-verification'),
    path('access-code/create/', AccessCodeCreateView.as_view(), name='access-code-create'),
    path('access-code/verified-count/', AccessCodeVerifiedCountView.as_view(), name='access-code-verified-count'),
    path('access-code/unapproved-count/', AccessCodeUnapprovedCountView.as_view(), name='access-code-unapproved-count'),
    path('alerts/', AlertListView.as_view(), name='alert-list'),
    path('alerts/create/', AlertCreateView.as_view(), name='alert-create'),
    path('visitor/checkin/', VisitorCheckinListView.as_view(), name='visitor-checkin-list'),
    path('access-codes/by-user/', AccessCodeByUserListView.as_view(), name='access-code-by-user-list'),
    path('access-codes/<str:code>/deactivate/', AccessCodeDeactivateView.as_view(), name='access-code-deactivate'),
    path('verify-and-credit/', VerifyAndCreditView.as_view(), name='verify-and-credit'),
    path('lostfound/', LostFoundItemListView.as_view(), name='lostfound-list'),
    path('lostfound/create/', LostFoundItemCreateView.as_view(), name='lostfound-create'),
    path('lostfound/<int:pk>/',LostFoundItemDetailView.as_view(), name='lost_found_detail'),
    path('api/access-code/verify/', AccessCodeVerifyView.as_view(), name='access_code_verify'),
    path('access-code/<str:code>/retrieve/', AccessCodeRetrieveView.as_view(), name='access_code_retrieve'),
   
]
