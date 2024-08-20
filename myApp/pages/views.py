from django.http import JsonResponse
from django.shortcuts import redirect, render

from django.shortcuts import HttpResponse
from django.contrib import messages
from . import models
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
import bcrypt
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator as token_generator
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
from django.db.models import Q
from django.core.paginator import Paginator
import pandas as pd
import re


def calculate_score(gender, age, urgency_level, waiting_time_days):
    gender_score = 20 if gender.lower() == 'female' else 15
    
    if age > 65 or age < 5:
        age_score = 30
    elif 5 <= age <= 10 or 55 <= age <= 65:
        age_score = 20
    else:
        age_score = 15
    
    urgency_mapping = {
        'ultra': 40,
        'high': 30,
        'medium': 20,
        'low': 10,
    }
    urgency_score = urgency_mapping.get(urgency_level.lower(), 0)
    
    if waiting_time_days < 10:
        waiting_time_score = 0
    elif 11 <= waiting_time_days <= 30:
        waiting_time_score = 5
    elif 31 <= waiting_time_days <= 60:
        waiting_time_score = 8
    else:
        waiting_time_score = 10
    
    total_score = gender_score + age_score + urgency_score + waiting_time_score
    return total_score

def addPat(request):
    if request.method == "POST":
        fullname = request.POST['full_name']
        email = request.POST['email']
        address = request.POST['address']
        phone = request.POST['phone']
        urgency_level = request.POST['urgency_level']
        age = int(request.POST['age'])
        gender = request.POST['gender']
        user_id = request.POST['id']
        action = request.POST['action']
        waiting_time_days = int(request.POST['waiting_time_days'])  
        score = calculate_score(gender, age, urgency_level, waiting_time_days)
        
        new_patient = models.Patient.objects.create(
            full_name=fullname,
            email=email,
            address=address,
            phone=phone,
            urgency_level=urgency_level,
            age=age,
            gender=gender,
            id=user_id,
            score=score,
            action=action,
        )
        new_patient.save()
        print (score)
        
        messages.success(request, f'Patient {fullname} added successfully!')
        return redirect('addPat')  
    return render(request, 'pages/addPat.html') 

def dash(request):
    search_query = request.GET.get('search', '')  
    age_from = request.GET.get('age_from')
    age_to = request.GET.get('age_to')
    score_from = request.GET.get('score_from')
    score_to = request.GET.get('score_to')
    gender = request.GET.getlist('gender')  
    print(search_query, age_from, age_to,score_from, score_to, gender)

    query = Q(full_name__icontains=search_query)

    if age_from:
        query &= Q(age__gte=age_from)
    if age_to:
        query &= Q(age__lte=age_to)
    if gender:  
        query &= Q(gender__in=gender)
    if score_from:
        query &= Q(score__gte=score_from)
    if score_to:
        query &= Q(score__lte=score_to)
        
    if search_query:
        patients = models.Patient.objects.filter(Q(full_name__icontains=search_query)).order_by('-date')
    else:
        patients = models.Patient.objects.all().order_by('-date')

    patients = models.Patient.objects.filter(query).order_by('-date')

    paginator = Paginator(patients, 5)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'age_from': age_from,
        'age_to': age_to,
        'gender': gender,
        'score_from': score_from,
        'score_to': score_to
    }
    
    return render(request, 'pages/dash.html', context)

def import_patients(request):
    if request.method == 'POST':
        patient_file = request.FILES['patient_file']

        try:
            df = pd.read_excel(patient_file)

            for index, row in df.iterrows():
                email = row['email']

                if models.Patient.objects.filter(email=email).exists():
                    continue  

                full_name = row['full_name']
                address = row['address']
                phone = row['phone']
                age = int(row['age'])
                gender = row['gender']
                urgency_level = row['urgency_level']
                action = row['action']
                
                score = calculate_score(gender, age, urgency_level, 0)
                
                models.Patient.objects.create(
                    full_name=full_name,
                    email=email,
                    address=address,
                    phone=phone,
                    age=age,
                    gender=gender,
                    urgency_level=urgency_level,
                    action=action,
                    score=score
                )

            messages.success(request, 'Patients imported successfully!')
        except Exception as e:
            messages.error(request, f'Error importing patients: {str(e)}')

        return redirect('addPat')

    return render(request, 'pages/addPat.html')
def Success(request):
    if 'user' in request.session:
        user_info = request.session['user']
        context = {
            'first_name': user_info['first_name'],
            'last_name': user_info['last_name']
        }
        return render(request,"pages/success.html",context)
    else:
        return HttpResponse("You are not logged in")
    
def index(request):
    return render(request,"pages/index.html")
def about(request):
    return render(request,"pages/about.html")

def create_user(id,fname, lname, email, passwd, phone):
    salt = bcrypt.gensalt()
    enc_pass = bcrypt.hashpw(passwd.encode(), salt).decode()
    new_user = models.Users.objects.create(
        first_name=fname,
        last_name=lname,
        email=email,
        phone=phone,
        password=enc_pass,
        id=id
    )
    return new_user

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = models.Users.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, models.Users.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('login') 
    else:
        return render(request, 'activation_invalid.html')  

    return render(request, 'activation_done.html')

def register(request):
    if request.method == "POST":
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        phone = request.POST['phone']
        email = request.POST['email']
        password = request.POST['password']
        password_confirmation = request.POST['password_confirmation']
        user_id = request.POST['id']
        errors = {}

        if len(first_name) < 2:
            errors['first_name'] = "First name must be at least 2 characters."
        if len(last_name) < 2:
            errors['last_name'] = "Last name must be at least 2 characters."
        if len(password) < 8 or not any(char.isalpha() for char in password):
            errors['password'] = "Password must be at least 8 characters long and contain at least one letter."
        if password != password_confirmation:
            errors['password_confirmation'] = "Passwords do not match."

        model_errors = models.Users.objects.basic_validator(request.POST)
        errors.update(model_errors)

        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/pages/register')
        else:
            user = create_user(user_id, first_name,last_name, email, password, phone)
            
            # Generate email verification token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)
            
            # Prepare email
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('pages/email_verification.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            })
            send_mail(
                mail_subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            
            messages.success(request, 'Please confirm your email address to complete the registration.')
            return redirect('login')
    
    return render(request, 'pages/register.html')

def edit_patient(request, id):
    patient = models.Patient.objects.get(id=id)
    print(id)
    if request.method == 'POST':
        patient.full_name = request.POST['full_name']
        patient.email = request.POST['email']
        patient.address = request.POST['address']
        patient.phone = request.POST['phone']
        patient.urgency_level = request.POST['urgency_level']
        patient.age = int(request.POST['age'])
        patient.gender = request.POST['gender']
        patient.action = request.POST['action']
        
        
        waiting_time_days = int(request.POST['waiting_time_days'])
        patient.score = calculate_score(patient.gender, patient.age, patient.urgency_level, waiting_time_days)
        
        patient.save()
        messages.success(request, f'Patient {patient.full_name} updated successfully!')
        return redirect('../../dash')

    return render(request, 'pages/edit_patient.html', {'patient': patient})

def delete_patient(request, id):
    patient = models.Patient.objects.get(id=id)
    
    if request.method == 'POST':
        patient.delete()
        messages.success(request, f'Patient {patient.full_name} deleted successfully!')
        return redirect('/pages/dash')
    
def login(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        user = models.Users.objects.filter(email=email).first()

        if user:
            if not user.is_active:
                error_message = "Your email address is not verified. Please check your email for the verification link."
                return render(request, 'pages/login.html', {'error_message': error_message})
            
            if bcrypt.checkpw(password.encode(), user.password.encode()):
                request.session['user'] = {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email
                }
                return redirect('/pages/success')
            else:
                error_message = "Invalid email or password."
        else:
            error_message = "Invalid email or password."

        return render(request, 'pages/login.html', {'error_message': error_message})
    
    return render(request, 'pages/login.html')




def Success1(request):
    if 'fname' not in request.session:
        return redirect('/pages/login')
    
    context = {
        'fname': request.session['fname'],
        'lname': request.session['lname'],
    }
    return render(request, "success.html", context)