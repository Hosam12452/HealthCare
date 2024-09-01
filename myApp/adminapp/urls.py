from django.urls import path
from django.contrib import admin  # Correct import for Django's admin site

urlpatterns = [
    path('admin/', admin.site.urls),  # Route for the admin panel
]