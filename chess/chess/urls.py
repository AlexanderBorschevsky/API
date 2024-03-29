"""
URL configuration for chess project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from chessbackend.views import *

urlpatterns = [
    path('', index),
    path('admin', admin.site.urls),
    path('api/v1/register', MyUserAPIList.as_view()),
    path('api/v1/login', Login.as_view(), name='check_user'),
    path('api/confirm-registration/<str:confirmation_token>', ConfirmRegistrationView.as_view(),
         name='confirm-registration'),
    path('hello', HelloWorldView.as_view(), name='hello_world'),
    path('api/v1/logout', Logout.as_view()),
    path('refresh-access-token', refresh_access_token, name='refresh_access_token'),
    path('authuser', AuthUser.as_view()),
    path('userlogin', UserLogin.as_view()),
    path('api/v1/password-reset', ResetPassword.as_view()),
    path('api/v1/password-reset/<str:confirmation_token>', ResetConfirmPassword.as_view(),name='password-reset')

    # path('logout/', Logout.as_view(), name='Logout'),
]
