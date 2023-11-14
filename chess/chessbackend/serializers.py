from rest_framework import serializers

from rest_framework.renderers import JSONRenderer

from .models import MyUser

class MyUserSerializer(serializers.ModelSerializer):
    # Добавляем поле password в сериализатор


    class Meta:
        model = MyUser
        fields = ['email', 'password']


