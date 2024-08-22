# Importing necessary Django modules and utilities
from django.db import models
import re
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin



# Define a custom manager for the Users model, including a basic validator for form validation
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


# Define the Users model with fields for user information, including custom manager and methods
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class Users(AbstractBaseUser, PermissionsMixin):
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


    # Method to set the user's password (hashing it)
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    # Method to check the password during authentication
    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    def get_email_field_name(self):
        return 'email'
    objects = UserManager()


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
