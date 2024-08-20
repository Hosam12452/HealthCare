from django.urls import path
from . import views
from .views import import_patients


urlpatterns=[
    path ('index',views.index,name='index'),
    path ('login',views.login,name='login'),
    path("success", views.Success,name="success"),
    path('register' ,views.register,name='register'),
    path('dash' ,views.dash,name='dash'),
    path('about' ,views.about,name='about'),
    path('addPat' ,views.addPat,name='addPat'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('import/', import_patients, name='import_patients'),

]