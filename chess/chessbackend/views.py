
from rest_framework_simplejwt.tokens import RefreshToken
from .service import EmailConfirmationService
from .models import MyUser
from rest_framework import generics, status
from .serializers import MyUserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response

# Create your views here.
class MyUserAPIList(generics.CreateAPIView):
    queryset = MyUser.objects.none()
    serializer_class = MyUserSerializer

    def create(self, request, *args, **kwargs):
        # Сериализация данных запроса
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Доступ к данным, которые прошли валидацию сериализатора
        user_data = serializer.validated_data

        # Создание пользователя с явным установлением атрибутов
        user = MyUser(email=user_data['email'])

        # Отправка сообщения об успешной регистрации на указанную почту
        EmailConfirmationService.send_registration_success_email(user_data['email'])

        # Сохранение пользователя в базе данных
        user.save()

        return Response({'message': 'Регистрация успешно выполнена. Письмо отправлено на указанную почту.'},
                        status=status.HTTP_201_CREATED)




class Login(APIView):
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

