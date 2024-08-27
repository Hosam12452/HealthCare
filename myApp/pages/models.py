
# Importing necessary Django modules and utilities
from django.conf import settings
from django.db import models
import re
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import BaseUserManager
from django.utils import timezone






# Define a custom manager for the Users model, including a basic validator for form validation
class UserManager(BaseUserManager):
    def basic_validator(self, postData):
        errors = {}

        if len(postData.get('first_name', '')) < 2:
            errors["first_name"] = "First name should be at least 2 characters!"
        if len(postData.get('last_name', '')) < 2:
            errors["last_name"] = "Last name should be at least 2 characters!"
        
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, postData.get('email', '')):
            errors["email"] = "Enter a valid email address!"
        
        password_regex = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
        password = postData.get('password', '')
        if not re.match(password_regex, password):
            errors["password"] = "Enter a valid password!"

        return errors

    def get_by_natural_key(self, username):
        return self.get(email=username)



class Users(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)  # Required by Django admin

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def get_full_name(self):
        return f'{self.first_name} {self.last_name}'

    def get_short_name(self):
        return self.first_name

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    def get_email_field_name(self):
        return 'email'
    
    objects = UserManager()


class UserLog(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    login_time = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.user.get_full_name()} logged in at {self.login_time}'


class EditLog(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    edit_time = models.DateTimeField(default=timezone.now)
    edited_field = models.CharField(max_length=255)  
    old_value = models.TextField()  
    new_value = models.TextField()  

    def __str__(self):
        return f'{self.user.get_full_name()} edited at {self.edit_time}'


class AddLog(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    add_time = models.DateTimeField(default=timezone.now)
    patient_name = models.CharField(max_length=255)

    def __str__(self):
        return f'{self.user.get_full_name()} added at {self.add_time}'


class DeleteLog(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    delete_time = models.DateTimeField(default=timezone.now)
    patient_name = models.CharField(max_length=255)

    def __str__(self):
        return f'{self.user.get_full_name()} deleted at {self.delete_time}'
    

# Define the Patient model with various fields, including choice fields for gender and urgency level
class Patient(models.Model):
    class UrgencyLevel(models.TextChoices):
        LOW = 'Low', 'Low'
        MEDIUM = 'Medium', 'Medium'
        HIGH = 'High', 'High'
        ULTRA = 'Ultra', 'Ultra'

    class Gender(models.TextChoices):
        MALE = 'Male', 'Male'
        FEMALE = 'Female', 'Female'

    class ActionPatient(models.TextChoices):
        UPDATE_MEDICAL_RECORDS = 'Update Medical Records', 'Update Medical Records'
        ORDER_DIAGNOSTIC_TESTS = 'Order Diagnostic Tests', 'Order Diagnostic Tests'
        REFER_TO_SPECIALIST = 'Refer to Specialist', 'Refer to Specialist'
        DISCHARGE_PATIENT = 'Discharge Patient', 'Discharge Patient'
        PROVIDE_HEALTH_EDUCATION = 'Provide Health Education', 'Provide Health Education'
        PERFORM_A_PROCEDURE = 'Perform a Procedure', 'Perform a Procedure'


    full_name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    email = models.EmailField(unique=False)
    status = models.CharField(max_length=255, default="")
    note = models.CharField(max_length=255, default="")
    age = models.IntegerField()
    gender = models.CharField(
        max_length=6,
        choices=Gender.choices,
    )
    date = models.DateTimeField(auto_now=True)
    urgency_level = models.CharField(
        max_length=6,
        choices=UrgencyLevel.choices,
    )
    score = models.IntegerField()
    action = models.CharField(
        max_length=255,
        choices=ActionPatient.choices,
    )



class Gender(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Action(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class UrgencyLevel(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Status(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name
    
class ScoreSettings(models.Model):
    gender_female_score = models.IntegerField(default=20)
    gender_male_score = models.IntegerField(default=15)

    age_above_65_or_below_5_score = models.IntegerField(default=30)
    age_between_5_and_10_or_55_and_65_score = models.IntegerField(default=20)
    age_others_score = models.IntegerField(default=15)

    urgency_ultra_score = models.IntegerField(default=40)
    urgency_high_score = models.IntegerField(default=30)
    urgency_medium_score = models.IntegerField(default=20)
    urgency_low_score = models.IntegerField(default=10)

    waiting_time_less_than_10_days_score = models.IntegerField(default=0)
    waiting_time_11_to_30_days_score = models.IntegerField(default=5)
    waiting_time_31_to_60_days_score = models.IntegerField(default=8)
    waiting_time_above_60_days_score = models.IntegerField(default=10)
