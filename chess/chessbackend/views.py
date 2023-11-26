import secrets
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .service import EmailConfirmationService
from .serializers import MyUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from .models import MyUser


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
        if email:
            user = MyUser.objects.filter(email=email).first()
        elif login:
            user = MyUser.objects.filter(login=login).first()

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
            {'message': 'Пользователь прошел проверку', 'access_token': str(access_token), 'refresh': str(refresh),
             'login': user.login})
        response.set_cookie('refresh_token', (refresh_token), max_age=refresh.lifetime.total_seconds(),
                            httponly=True, samesite='None', secure=False)

        return response


class UserLogin(APIView):
    def put(self, request):
        new_login = request.data.get('login')
        refresh_token = request.COOKIES.get('refresh_token')
        refresh_token = RefreshToken(refresh_token)
        refresh_token.payload.get('user_id')
        user_id = refresh_token['user_id']

        try:
            user = MyUser.objects.get(id=user_id)

            if new_login:
                user.login = new_login
                user.save()

            # Другие операции, если нужны

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
        print(user)
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
                user_email = user.email
                user_login = user.login

                new_refresh_token = RefreshToken.for_user(user)
                response_data = {
                    'access_token': access_token,
                    'email': user_email,
                    'login': user_login
                }
                response = JsonResponse(response_data)
                response.set_cookie(
                    'refresh_token',
                    str(new_refresh_token),
                    max_age=new_refresh_token.lifetime.total_seconds(),
                    httponly=True,
                    samesite='None',
                    secure=True,
                )
                return response

        except MyUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
