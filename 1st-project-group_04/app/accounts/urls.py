from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views

from accounts import views


app_name = 'accounts'

urlpatterns = [
    path('register/', views.user_register, name='user_register'),
    path('login/', views.user_login, name='user_login'),
    path('login/manager/', views.manager_login, name='manager_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('profile/<int:userid>', views.edit_profile, name='edit_profile'),
]

