from django.urls import path
from . import views

urlpatterns=[
    path ('index',views.index,name='index'),
    path ('login',views.login,name='login'),
    path("success", views.Success,name="success"),
    path('register' ,views.register,name='register'),
    path('dash' ,views.dash,name='dash'),
    path('about' ,views.about,name='about'),
    path('addPat' ,views.addPat,name='addPat'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('import/', views.import_patients, name='import_patients'),
    path('edit_patient/<int:id>/', views.edit_patient, name='edit_patient'),
    path('delete_patient/<int:id>/', views.delete_patient, name='delete_patient'),


]