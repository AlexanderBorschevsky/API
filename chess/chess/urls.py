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
from rest_framework_simplejwt.views import TokenObtainPairView

from chessbackend.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/createuser/',MyUserAPIList.as_view()),
    path('api/check_user/', Login.as_view(), name='check_user'),
    #path('api/confirm-registration/<str:confirmation_token>/', ConfirmRegistrationView.as_view(), name='confirm-registration'),
    path('hello/', HelloWorldView.as_view(), name='hello_world'),

   # path('logout/', Logout.as_view(), name='Logout'),
]
