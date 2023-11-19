import secrets

from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .service import EmailConfirmationService
from .models import MyUser
from rest_framework import generics, status, response
from .serializers import MyUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response


# Create your views here.
class MyUserAPIList(APIView):
    def generate_confirmation_token(self):
        # Генерация уникального токена
        return secrets.token_urlsafe(16)

    def post(self, request, *args, **kwargs):
        serializer = MyUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save(confirmation_token=self.generate_confirmation_token())
        EmailConfirmationService.send_registration_email(user.email, user.confirmation_token)

        return Response({
            'message': 'Регистрация успешно выполнена. Письмо отправлено на указанную почту.',
            'confirmation_token': user.confirmation_token
        }, status=status.HTTP_201_CREATED)


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
        password = request.data.get('password')

        user = MyUser.objects.filter(email=email).first()

        if user is None:
            return Response({'message': 'Пользователь не найден'}, status=400)

        if not user.is_email_confirmed():
            return Response({'message': 'Подтвердите почту'}, status=400)

        if not user.check_password(password):
            return Response({'message': 'Неверный пароль'}, status=400)
        refresh = (RefreshToken.for_user(user))
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        # print("Token payload:", access_token.payload)
        print(type(refresh))
        print(type(access_token))

        response = Response(
            {'message': 'Пользователь прошел проверку', 'access_token': str(access_token), 'refresh': str(refresh)})
        response.set_cookie('refresh_token', (refresh_token), max_age=refresh.lifetime.total_seconds(),
                             httponly=True,samesite='None',secure=True)

        return response


class HelloWorldView(APIView):
    authentication_classes = [JWTAuthentication]  # Замените на используемый вами класс аутентификации
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        print(user)
        return Response({'message': 'Hello, World!'})
class Logout(APIView):
    def get(self,request):
        response = redirect('api/v1/login')  # Замените 'your_redirect_url' на URL, на который вы хотите перенаправить пользователя после выхода
        response.delete_cookie('refresh_token')

        return response


@csrf_exempt
def refresh_access_token(request):
    if request.method == 'POST':
        # Получаем refresh токен из куки
        refresh_token_value = request.COOKIES.get('refresh_token')
        print(refresh_token_value)

        if refresh_token_value:
            # Пытаемся создать новый access токен
            try:
                refresh_token = RefreshToken(refresh_token_value)
                access_token = str(refresh_token.access_token)

                # Устанавливаем новый access токен в куку
                response = JsonResponse({'access_token': access_token})
                response.set_cookie('refresh_token', refresh_token, httponly=True,samesite='None',secure=True)
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'detail': 'Invalid request method'}, status=400)