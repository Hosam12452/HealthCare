from django import views
from django.test import TestCase
from django.urls import path

urlpatterns = [
path("success", views.Success1),
path("register", views.register),
path("login", views.login),
]
# Create your tests here.
