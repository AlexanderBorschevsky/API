import re

from django.utils.crypto import get_random_string
from rest_framework import serializers


from .models import MyUser


class MyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['email', 'password', 'login']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        if not re.search(r'\d', password) or \
                not re.search(r'[a-z]', password) or \
                not re.search(r'[A-Z]', password) or \
                not re.search(r'[!@#$%^&*(),.?":{}|<>]', password) or\
                len(password)<8:
                    raise serializers.ValidationError(
                        "Пароль должен быть не менее 8 символов, содержать хотя бы одну цифру, одну строчную и прописную буквы, а также один из следующих символов: !@#$%^&*(),.?\":{}|<>"
                    )
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

