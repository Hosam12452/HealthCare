from django.contrib import admin
from pages.models import Patient, Users

from pages.models import Users, Patient, Gender, Action, UrgencyLevel, Status , ScoreSettings,DeleteLog,AddLog,EditLog,UserLog

admin.site.register(Users)
admin.site.register(Patient)
admin.site.register(Gender)
admin.site.register(Action)
admin.site.register(UrgencyLevel)
admin.site.register(Status)
admin.site.register(ScoreSettings)
admin.site.register(UserLog)
admin.site.register(EditLog)
admin.site.register(AddLog)
admin.site.register(DeleteLog)

