import jwt
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


from .models import MyUser
from rest_framework import generics, viewsets, status
from rest_framework.views import APIView
from .serializers import MyUserSerializer
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import (
	AbstractBaseUser, BaseUserManager, PermissionsMixin
)

# Create your views here.
class MyUserAPIList(generics.ListCreateAPIView):
    queryset = MyUser.objects.all()
    serializer_class = MyUserSerializer



from rest_framework.views import APIView
from rest_framework.response import Response
from .models import MyUser

from rest_framework.views import APIView
from rest_framework.response import Response
from .models import MyUser

class CheckUserView(APIView):
    def post(self, request):
        email = request.data.get('email')
        login = request.data.get('login')
        password = request.data.get('password')

        if not (email or login):
            return Response({'message': 'Введите email или login'}, status=400)

        # Проверьте наличие пользователя в базе данных
        user = None
        if email:
            user = MyUser.objects.filter(email=email).first()
        elif login:
            user = MyUser.objects.filter(login=login).first()

        if user is None:
            return Response({'message': 'Пользователь не найден'}, status=400)

        # Проверьте пароль пользователя
        if not user.check_password(password):
            return Response({'message': 'Неверный пароль'}, status=400)


        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response(
            {'message': 'Пользователь прошел проверку', 'access_token': access_token, 'refresh': str(refresh)})
        response.set_cookie('refresh_token', str(refresh), max_age=refresh.lifetime.total_seconds(),
                            secure=True, httponly=True)

        return response

###