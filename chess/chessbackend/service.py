from django.core.mail import send_mail
from rest_framework.reverse import reverse

from chess import settings


class EmailConfirmationService:
    @staticmethod
    def send_registration_email(email, confirmation_token):
        subject = 'Регистрация успешна'
        confirmation_url = reverse('confirm-registration', args=[confirmation_token])
        full_confirm_url = settings.BASE_URL + confirmation_url
        message = f'Спасибо за регистрацию на нашем сайте. Ваш аккаунт успешно создан. Пожалуйста, подтвердите его, перейдя по ссылке: {full_confirm_url }'
        from_email = 'enjoychess@yandex.ru'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)