from django.core.mail import send_mail

class EmailConfirmationService:
    @staticmethod
    def send_registration_success_email(email):
        subject = 'Регистрация успешна'
        message = 'Спасибо за регистрацию на нашем сайте. Ваш аккаунт успешно создан.'
        from_email = 'aborschevscky@yandex.ru'  # Замените на ваш реальный адрес электронной почты
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)
