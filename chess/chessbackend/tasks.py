# tasks.py
from celery import shared_task
from .service import EmailConfirmationService  # Подставьте свой путь к сервису
from .serializers import MyUserSerializer  # Подставьте свой путь к сериализатору

@shared_task()
def send_registration_email_task(email, confirmation_token):
    EmailConfirmationService.send_registration_email(email, confirmation_token)
