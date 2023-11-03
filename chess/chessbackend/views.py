from django.shortcuts import render
from .models import MyUser
from rest_framework import generics, viewsets
from rest_framework.views import APIView
from .serializers import MyUserSerializer
# Create your views here.
class MyUserAPIList(generics.ListCreateAPIView):
    queryset = MyUser.objects.all()
    serializer_class = MyUserSerializer