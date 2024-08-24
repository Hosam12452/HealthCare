from django.urls import path
from . import views

urlpatterns=[
    path ('',views.index,name='index'),
    path ('login/',views.login_user,name='login'),
    path ('logout',views.logout_user,name='logout'),
    path("success/", views.Success,name="success"),
    path('register/' ,views.register,name='register'),
    path('dash/' ,views.dash,name='dash'),
    path('about/' ,views.about,name='about'),
    path('addPat/' ,views.addPat,name='addPat'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('import_patient/', views.import_patients, name='import_patients'),
    path('edit_patient/<int:id>/', views.edit_patient, name='edit_patient'),
    path('delete_patient/<int:id>/', views.delete_patient, name='delete_patient'),
    path('admin_dashbord/', views.admin_dashbord, name='admin_dashbord'),
    path('manage-genders/', views.manage_genders, name='manage_genders'),
    path('manage-actions/', views.manage_actions, name='manage_actions'),
    path('manage-urgency-levels/', views.manage_urgency_levels, name='manage_urgency_levels'),
    path('manage_stauts/', views.manage_stauts, name='manage_stauts'),


]