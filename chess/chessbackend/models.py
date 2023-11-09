from datetime import date
from django.contrib.auth.hashers import check_password

from django.contrib.auth.hashers import make_password


# Create your models here.
from django.db import models
from django.utils.crypto import get_random_string


class MyUser(models.Model):
    email = models.EmailField(max_length=70, unique=True)
    login = models.CharField(max_length=20, unique=True, null=True,blank=True)
    password = models.CharField(max_length=255)
    registration_date = models.DateField(default=date.today)
    email_confirmed = models.BooleanField(default=False)
    confirmation_token = models.CharField(max_length=64, blank=True, null=True)

    def save(self, *args, **kwargs):
        # Хешируем пароль перед сохранением
        self.password = make_password(self.password)
        super(MyUser, self).save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
