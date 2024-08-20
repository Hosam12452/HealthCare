from django.db import models
import re

class Student(models.Model):
    first_name = models.CharField(max_length=45)
    last_name = models.CharField(max_length=45)
    email = models.EmailField()

class Course(models.Model):
    name = models.CharField(max_length=255)
    student = models.ForeignKey(Student, related_name="courses", on_delete=models.CASCADE)

class UserManager(models.Manager):
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

    USERNAME_FIELD = 'email'

    def get_email_field_name(self):
        return 'email'
    objects = UserManager()

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
