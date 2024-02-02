from datetime import date
from django.contrib.auth.models import AbstractUser
from django.db import models


class MyUser(AbstractUser):
    last_name = None
    last_login = None
    is_superuser = None
    first_name = None
    date_joined = None
    email = models.EmailField(max_length=70, unique=True)
    login = models.CharField(max_length=20, unique=True, null=True, blank=True)
    password = models.CharField(max_length=255)
    registration_date = models.DateField(default=date.today)
    email_confirmed = models.BooleanField(default=False)
    confirmation_token = models.CharField(max_length=64, blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
