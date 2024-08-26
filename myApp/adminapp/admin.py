from django.contrib import admin
from pages.models import Patient, Users

from pages.models import Users, Patient, Gender, Action, UrgencyLevel, Status , ScoreSettings

admin.site.register(Users)
admin.site.register(Patient)
admin.site.register(Gender)
admin.site.register(Action)
admin.site.register(UrgencyLevel)
admin.site.register(Status)
admin.site.register(ScoreSettings)
