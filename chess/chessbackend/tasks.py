# tasks.py
from celery import shared_task
from django.core.mail import send_mail
from rest_framework.reverse import reverse

from .service import EmailConfirmationService, BASE_URL  # Подставьте свой путь к сервису
from .serializers import MyUserSerializer  # Подставьте свой путь к сериализатору

@shared_task()
def send_registration_email_task(email, confirmation_token):
    subject = 'Регистрация успешна'
    confirmation_url = reverse('confirm-registration', args=[confirmation_token])
    full_confirm_url = BASE_URL + confirmation_url
    message = f'Спасибо за регистрацию на нашем сайте. Ваш аккаунт успешно создан. Пожалуйста, подтвердите его, перейдя по ссылке: {full_confirm_url}'
    from_email = 'enjoychess@yandex.ru'
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)
