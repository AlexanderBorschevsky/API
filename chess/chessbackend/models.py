from datetime import date

from django.db import models
from django.contrib.auth.hashers import make_password
from django.utils import timezone

# Create your models here.
from django.db import models


class MyUser(models.Model):
    email = models.EmailField(max_length=70, unique=True)
    login = models.CharField(max_length=20, unique=True, null=True)
    password = models.CharField(max_length=255)
    # custom_id = models.AutoField(primary_key=True)
    registration_date = models.DateField(default=date.today)
    # achievments = models.

    def save(self, *args, **kwargs):
        # Хешируем пароль перед сохранением
        self.password = make_password(self.password)
        super(MyUser, self).save(*args, **kwargs)