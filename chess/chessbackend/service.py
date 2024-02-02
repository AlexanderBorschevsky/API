from django.core.mail import send_mail
from rest_framework.reverse import reverse

BASE_URL = 'https://shiferchess.ru'


class EmailConfirmationService:
    @staticmethod
    def send_registration_email(email, confirmation_token):
        subject = 'Регистрация успешна'
        confirmation_url = reverse('confirm-registration', args=[confirmation_token])
        full_confirm_url = BASE_URL + confirmation_url
        message = f'Спасибо за регистрацию на нашем сайте. Ваш аккаунт успешно создан. Пожалуйста, подтвердите его, перейдя по ссылке: {full_confirm_url}'
        from_email = 'enjoychess@yandex.ru'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)


class PasswordResetService:
    @staticmethod
    def reset_password(email, confirmation_token):
        subject = 'Сброс пароля'
        reset_url = reverse('password-reset', args=[confirmation_token])
        full_reset_url = BASE_URL + reset_url
        message = f'Для сброса пароля перейдите по ссылке: {full_reset_url}'
        from_email = 'enjoychess@yandex.ru'
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)
