from django.contrib.auth.hashers import make_password, check_password
from django.http import HttpResponse
from django.utils.crypto import get_random_string
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from .service import EmailConfirmationService
from .models import MyUser
from rest_framework import generics, status, response
from .serializers import MyUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response

# Create your views here.
class MyUserAPIList(generics.CreateAPIView):
    queryset = MyUser.objects.none()
    serializer_class = MyUserSerializer
    def create(self, request, *args, **kwargs):
        password = request.data.get('password')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.validated_data
        confirmation_token = get_random_string(length=32)
        user = MyUser(email=user_data['email'], confirmation_token=confirmation_token, email_confirmed=False)
        user.password = make_password(password)
        user.save()
        EmailConfirmationService.send_registration_email(user_data['email'],confirmation_token)
        return Response({'message': 'Регистрация успешно выполнена. Письмо отправлено на указанную почту.','confirmation_token':confirmation_token},
                        status=status.HTTP_201_CREATED,)

class ConfirmRegistrationView(APIView):
    def get(self, request, confirmation_token):

        print(f"ConfirmRegistrationView called with token: {confirmation_token}")
        user = get_object_or_404(MyUser, confirmation_token=confirmation_token)
        user.email_confirmed = True
        user.save()
        print(f"User {user.email} confirmed successfully.")
        return Response({'message': 'Регистрация подтверждена успешно.'}, status=status.HTTP_200_OK)


class Login(APIView):
    def post(self, request):
        email = request.data.get('email')
        login = request.data.get('login')
        password=request.data.get('password')

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

        if not user.is_email_confirmed():
            return Response({'message': 'Подтвердите почту'}, status=400)

        if not check_password(password,user.password):
            return Response({'message': 'Неверный пароль'}, status=400)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = Response(
            {'message': 'Пользователь прошел проверку', 'access_token': str(access_token), 'refresh': str(refresh)})
        response.set_cookie('refresh_token', str(refresh), max_age=refresh.lifetime.total_seconds(),
                            secure=True, httponly=True)

        return response

class HelloWorldView(APIView):
    authentication_classes = [JWTAuthentication]  # Замените на используемый вами класс аутентификации
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        print(user)
        return Response({'message': 'Hello, World!'})
