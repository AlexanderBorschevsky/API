from django.shortcuts import render
from .models import MyUser
from rest_framework import generics, viewsets
from rest_framework.views import APIView
from .serializers import MyUserSerializer
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

        return Response({'message': 'Пользователь прошел проверку'}, status=200)
