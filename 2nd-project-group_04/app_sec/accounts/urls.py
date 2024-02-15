from django.urls import path, reverse_lazy
from accounts import views
from django.contrib.auth.views import LoginView
from django_otp.forms import OTPAuthenticationForm

app_name = 'accounts'

urlpatterns = [
    path('register/', views.user_register, name='user_register'),
    path('login/', views.user_login, name='user_login'),
    path('login/2step', views.otp_view, name='user_login_2s'),
    path('reauth/2step', views.otp_view_verify, name='reauth_2s'),
    path('login/manager/', views.manager_login, name='manager_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('profile/edit', views.edit_profile, name='edit_profile'),
    path('profile/changepassword', views.change_password, name="change_password"),
    path('profile/delete', views.delete_account, name='delete_account'),
]

