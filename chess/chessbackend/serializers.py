from rest_framework import serializers

from rest_framework.renderers import JSONRenderer

from .models import MyUser

class MyUserSerializer(serializers.ModelSerializer):
    user=serializers.HiddenField(default=serializers.CurrentUserDefault())
    class Meta:
        model=MyUser
        fields= ('login','password','email')

