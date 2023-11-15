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




    def is_email_confirmed(self):
        return self.email_confirmed
