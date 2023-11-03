from django.db import models
from django.contrib.auth.hashers import make_password

# Create your models here.
from django.db import models

class MyUser(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField(max_length=500, unique=True)
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        # Хешируем пароль перед сохранением
        self.password = make_password(self.password)
        super(MyUser, self).save(*args, **kwargs)
