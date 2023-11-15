from rest_framework import serializers

from rest_framework.renderers import JSONRenderer

from .models import MyUser

class MyUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = MyUser
        fields = ['email', 'password','login']


