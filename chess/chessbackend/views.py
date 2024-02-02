import re
import secrets
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .service import EmailConfirmationService, PasswordResetService
from .serializers import MyUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse, HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken
from .models import MyUser


def index(request):
    return HttpResponse('Сайт работает!')


# Create your views here.
class MyUserAPIList(APIView):
    def generate_confirmation_token(self):
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
    def get(self, confirmation_token):
        user = get_object_or_404(MyUser, confirmation_token=confirmation_token)
        user.email_confirmed = True
        user.confirmation_token = None
        user.save()
        return Response({'message': 'Регистрация подтверждена успешно.'}, status=status.HTTP_200_OK)


class Login(APIView):
    def post(self, request):
        email = request.data.get('email')
        login = request.data.get('login')
        password = request.data.get('password')
        user = MyUser.objects.get(email=email)
        if email:
            user = MyUser.objects.get(email=email)
        elif login:
            user = MyUser.objects.get(login=login)
        if user is None:
            return Response({'message': 'Пользователь не найден'}, status=400)
        if user.email_confirmed is False:
            return Response({'message': 'Подтвердите почту'}, status=400)
        if not user.check_password(password):
            return Response({'message': 'Неверный пароль'}, status=400)
        refresh_token = RefreshToken.for_user(user)
        access_token = str(refresh_token.access_token)
        response = JsonResponse(
            {'message': 'Пользователь прошел проверку', 'access_token': access_token, 'refresh': str(refresh_token),
             'login': user.login})
        response.set_cookie('refresh_token', refresh_token, max_age=refresh_token.lifetime.total_seconds(),
                            httponly=True, samesite='None', secure=True)
        return response


class UserLogin(APIView):
    def put(self, request):
        new_login = request.data.get('login')
        refresh_token_old = request.COOKIES.get('refresh_token')
        refresh_token = RefreshToken(refresh_token_old)
        user_id = refresh_token.payload.get('user_id')
        try:
            user = MyUser.objects.get(id=user_id)
            if new_login:
                user.login = new_login
                user.save()
            return Response({'message': 'Логин успешно обновлен', 'login': user.login}, status=status.HTTP_200_OK)
        except MyUser.DoesNotExist:
            return Response({'error': 'Пользователь не найден'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class HelloWorldView(APIView):
    authentication_classes = [JWTAuthentication]  # Замените на используемый вами класс аутентификации
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({'message': 'Hello, World!'})


class Logout(APIView):
    def post(self, request, *args, **kwargs):
        if 'refresh_token' in request.COOKIES:
            response = Response(
                {'message': 'Пользователь прошел проверку'})
            response.set_cookie('refresh_token', 'invalide', max_age=0, httponly=True, samesite='None', secure=True)
            return response
        else:
            return Response({'detail': 'No refresh token found'}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
def refresh_access_token(request):
    if request.method == 'POST':

        refresh_token_value = request.COOKIES.get('refresh_token')

        if refresh_token_value:
            try:
                refresh_token = RefreshToken(refresh_token_value)
                access_token = str(refresh_token.access_token)
                user_id = refresh_token.payload.get('user_id')
                user = MyUser.objects.get(id=user_id)
                new_refresh_token = RefreshToken.for_user(user)
                response = JsonResponse({'access_token': access_token})
                response.set_cookie('refresh_token', new_refresh_token,
                                    max_age=new_refresh_token.lifetime.total_seconds(), httponly=True, samesite='None',
                                    secure=True)
                return response
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'detail': 'Invalid request method'}, status=400)


class AuthUser(APIView):
    def post(self, request):
        try:
            refresh_token_value = request.COOKIES.get('refresh_token')
            if refresh_token_value:
                refresh_token = RefreshToken(refresh_token_value)
                access_token = str(refresh_token.access_token)
                user_id = refresh_token.payload.get('user_id')
                user = MyUser.objects.get(id=user_id)

                new_refresh_token = RefreshToken.for_user(user)
                response_data = {
                    'access_token': access_token,
                    'email': user.email,
                    'login': user.login
                }
                response = JsonResponse(response_data)
                response.set_cookie(
                    'refresh_token',
                    new_refresh_token,
                    max_age=new_refresh_token.lifetime.total_seconds(),
                    httponly=True,
                    samesite='None',
                    secure=True,
                )
                return response
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResetPassword(APIView):
    def generate_confirmation_token(self):
        return secrets.token_urlsafe(16)

    def post(self, request):
        user_email = request.data.get('email')
        if not user_email:
            return Response({'error': 'User_email not found'}, status=status.HTTP_400_BAD_REQUEST)
        if user_email:
            user = MyUser.objects.get(email=user_email)
            user.confirmation_token = self.generate_confirmation_token()
            user.save()
        else:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        PasswordResetService.reset_password(user.email, user.confirmation_token)
        return Response({
            'message': 'Для сброса пароля, перейдите на указанную почту .',
            'confirmation_token': user.confirmation_token
        }, status=status.HTTP_201_CREATED)


class ResetConfirmPassword(APIView):
    def post(self, request, confirmation_token):
        password = request.data.get('password')
        user = get_object_or_404(MyUser, confirmation_token=confirmation_token)
        if not re.search(r'\d', password) or \
                not re.search(r'[a-z]', password) or \
                not re.search(r'[A-Z]', password) or \
                not re.search(r'[@.#$!%*_?&^]', password) or \
                len(password) < 8:
            return Response(
                "Пароль должен быть не менее 8 символов, содержать хотя бы одну цифру, одну строчную и прописную буквы, а также один из следующих символов: @.#$!%*_?&^"
            )
        else:
            user.password = make_password(password)
            user.confirmation_token = None
            user.save()
            return Response({'message': 'Поздравляем, ваш пароль успешно обновлен.'}, status=status.HTTP_200_OK)
