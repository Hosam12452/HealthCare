from django.urls import path
from . import views
from .views import PatientListAPIView,PatientDetailView

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
    path('generate_report/', views.generate_report, name='generate_report'),
    path('log_time/', views.log_time, name='log_time'),
    path('export/edit-logs/', views.export_edit_logs, name='export_edit_logs'),
    path('export/user-logs/', views.export_user_logs, name='export_user_logs'),
    path('export/add-logs/', views.export_add_logs, name='export_add_logs'),
    path('export/delete-logs/', views.export_delete_logs, name='export_delete_logs'),
    path('api/patients/', PatientListAPIView.as_view(), name='patient-list'),
    path('api/patients/<int:pk>/', PatientDetailView.as_view(), name='patient-detail'),
    path('export_patients/', views.export_patients, name='export_patients'),
    path("test_api/", views.test_api,name="test_api"),
    path('reports/', views.reports, name='reports'),
    path('reports/delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path("contact_us/", views.contact_us,name="contact_us"),

]