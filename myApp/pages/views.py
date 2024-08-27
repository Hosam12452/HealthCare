from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.shortcuts import HttpResponse
from django.contrib import messages
from . import models
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
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
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
import pandas as pd
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .models import Users
import bcrypt as bcrypt
from django.template.loader import get_template
from xhtml2pdf import pisa
from io import BytesIO
import matplotlib.pyplot as plt
from io import BytesIO
from django.core.files.base import ContentFile
import numpy as np
import base64
from django.utils import timezone
import csv


def export_edit_logs(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="edit_logs.csv"'

    writer = csv.writer(response)
    writer.writerow(['Full Name', 'Edit Time', 'Edited Field', 'Old Value', 'New Value'])

    for log in models.EditLog.objects.all():
        writer.writerow([log.user.get_full_name(), log.edit_time, log.edited_field, log.old_value, log.new_value])

    return response


def export_user_logs(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="user_logs.csv"'

    writer = csv.writer(response)
    writer.writerow(['Full Name', 'Login Time'])

    for log in models.UserLog.objects.all():
        writer.writerow([log.user.get_full_name(), log.login_time])

    return response


def export_add_logs(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="add_logs.csv"'

    writer = csv.writer(response)
    writer.writerow(['Full Name', 'Add Time', 'Patient Name'])

    for log in models.AddLog.objects.all():
        writer.writerow([log.user.get_full_name(), log.add_time, log.patient_name])

    return response


def export_delete_logs(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="delete_logs.csv"'

    writer = csv.writer(response)
    writer.writerow(['Full Name', 'Delete Time', 'Patient Name'])

    for log in models.DeleteLog.objects.all():
        writer.writerow([log.user.get_full_name(), log.delete_time, log.patient_name])

    return response


def log_time(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    user = request.GET.get('user')

    edit_logs = models.EditLog.objects.all()
    if start_date:
        edit_logs = edit_logs.filter(edit_time__date__gte=start_date)
    if end_date:
        edit_logs = edit_logs.filter(edit_time__date__lte=end_date)
    if user:
        edit_logs = edit_logs.filter(user=user)

    user_logs = models.UserLog.objects.all()
    if start_date:
        user_logs = user_logs.filter(login_time__date__gte=start_date)
    if end_date:
        user_logs = user_logs.filter(login_time__date__lte=end_date)
    if user:
        user_logs = user_logs.filter(user=user) 

    add_logs = models.AddLog.objects.all()
    if start_date:
        add_logs = add_logs.filter(add_time__date__gte=start_date)
    if end_date:
        add_logs = add_logs.filter(add_time__date__lte=end_date)
    if user:
        add_logs = add_logs.filter(user=user) 

    delete_logs = models.DeleteLog.objects.all()
    if start_date:
        delete_logs = delete_logs.filter(delete_time__date__gte=start_date)
    if end_date:
        delete_logs = delete_logs.filter(delete_time__date__lte=end_date)
    if user:
        delete_logs = delete_logs.filter(user=user) 

    context = {
        'edit_logs': edit_logs,
        'user_logs': user_logs,
        'add_logs': add_logs,
        'delete_logs': delete_logs,
    }
    return render(request, 'pages/log_time.html', context)


#View function to view the index page
def index(request):
    return render(request,"pages/index.html")


#View function to view the about page
def about(request):
    return render(request,"pages/about.html")


#Function for register the user into the system, include send the email verfication 
def register(request):
    if 'user_id' in request.session:
        messages.error(request, "Please log out before accessing the regester.")
        return redirect('dash')
    
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
            # Hash the password with bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            user = models.Users.objects.create(
                id=user_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=hashed_password,
                phone=phone
            )
            
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


def generate_report(request):
    page_number = request.GET.get('page', 1)
    search_query = request.GET.get('search', '')
    age_from = request.GET.get('age_from')
    age_to = request.GET.get('age_to')
    score_from = request.GET.get('score_from')
    score_to = request.GET.get('score_to')
    gender = request.GET.getlist('gender')

    # Build the query object for filtering patients
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

    # Filter patients based on the query
    patients = models.Patient.objects.filter(query).order_by('-score')

    # Paginate the patients
    paginator = Paginator(patients, 6)  # Same page size as the dashboard
    page_obj = paginator.get_page(page_number)

    # Create a distribution chart based on the name and score of the patients
    names = [patient.full_name for patient in page_obj]
    scores = [patient.score for patient in page_obj]

    plt.figure(figsize=(8, 5))
    plt.barh(names, scores, color='skyblue')
    plt.xlabel('Score')
    plt.ylabel('Patient Name')
    plt.title('Patient Score Distribution')

    # Save the plot to a BytesIO object
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)

    # Encode the image to base64 to embed in the HTML template
    image_png = buffer.getvalue()
    chart_base64 = base64.b64encode(image_png).decode('utf-8')

    # Include the chart in the context
    context = {
        'page_obj': page_obj,
        'chart_base64': chart_base64,
    }

    # Generate the PDF
    template = get_template('pages/report_template.html')
    html = template.render(context)
    response = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), response)

    if not pdf.err:
        return HttpResponse(response.getvalue(), content_type='application/pdf')
    else:
        return HttpResponse('We had some errors generating the report', status=500)




# View function to login to the system
def login_user(request):
    if 'user_id' in request.session:
        messages.error(request, "Please log out before accessing the login.")
        return redirect('dash')
    
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            user = None
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            if not user.is_active:
                error_message = "Your email address is not verified. Please check your email for the verification link."
                return render(request, 'pages/login.html', {'error_message': error_message})
            
            request.session['user_id'] = user.id
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name

            models.UserLog.objects.create(user=user)
            
            return redirect('/pages/dash')
        else:
            error_message = "Invalid email or password."
            return render(request, 'pages/login.html', {'error_message': error_message})
    
    return render(request, 'pages/login.html')



def logout_user(request):
    # Clear the session data to log the user out
    request.session.flush()
    messages.success(request, "You have been logged out successfully.")
    return redirect('login') 


# Function to calculate a patient's score based on gender, age, urgency level, and waiting time
def calculate_score(gender, age, urgency_level, waiting_time_days):
    score_settings = models.ScoreSettings.objects.first()  # Assuming you have only one settings object

    gender_score = score_settings.gender_female_score if gender.lower() == 'female' else score_settings.gender_male_score

    if age > 65 or age < 5:
        age_score = score_settings.age_above_65_or_below_5_score
    elif 5 <= age <= 10 or 55 <= age <= 65:
        age_score = score_settings.age_between_5_and_10_or_55_and_65_score
    else:
        age_score = score_settings.age_others_score

    urgency_mapping = {
        'ultra': score_settings.urgency_ultra_score,
        'high': score_settings.urgency_high_score,
        'medium': score_settings.urgency_medium_score,
        'low': score_settings.urgency_low_score,
    }
    urgency_score = urgency_mapping.get(urgency_level.lower(), 0)

    if waiting_time_days < 10:
        waiting_time_score = score_settings.waiting_time_less_than_10_days_score
    elif 11 <= waiting_time_days <= 30:
        waiting_time_score = score_settings.waiting_time_11_to_30_days_score
    elif 31 <= waiting_time_days <= 60:
        waiting_time_score = score_settings.waiting_time_31_to_60_days_score
    else:
        waiting_time_score = score_settings.waiting_time_above_60_days_score

    total_score = gender_score + age_score + urgency_score + waiting_time_score
    return total_score


# View function for the dashboard, including search, filtering, and pagination
def dash(request):
    if 'user_id' not in request.session:
        messages.error(request, "Please log in before accessing the dashboard.")
        return redirect('login')
    
    search_query = request.GET.get('search', '')  
    age_from = request.GET.get('age_from')
    age_to = request.GET.get('age_to')
    score_from = request.GET.get('score_from')
    score_to = request.GET.get('score_to')
    gender = request.GET.getlist('gender')  
    print(search_query, age_from, age_to,score_from, score_to, gender)


    # Build the query object for filtering patients
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
        

    # Filter patients based on search and other criteria
    if search_query:
        patients = models.Patient.objects.filter(Q(full_name__icontains=search_query)).order_by('-date')
    else:
        patients = models.Patient.objects.all().order_by('-date')

    patients = models.Patient.objects.filter(query).order_by('-date')

    paginator = Paginator(patients, 6)  
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

# View function to add a new patient

def addPat(request):
    if 'user_id' not in request.session:
        messages.error(request, "Please log in before accessing this site !.")
        return redirect('login')
    
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
        status = request.POST['status']
        note = request.POST['note']
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
            status=status,
            note=note,
        )
        new_patient.save()
        print (score)
        user = Users.objects.get(id=request.session["user_id"])
        models.AddLog.objects.create(

            user=user,
            add_time=timezone.now(),
            patient_name=fullname
        )
        
        messages.success(request, f'Patient {fullname} added successfully!')
        return redirect('addPat')  
    genders = models.Gender.objects.all()
    actions = models.Action.objects.all()
    urgency_levels = models.UrgencyLevel.objects.all()
    statuses = models.Status.objects.all()
    
    context = {
        'genders': genders,
        'actions': actions,
        'urgency_levels': urgency_levels,
        'statuses': statuses,
    }
    
    return render(request, 'pages/addPat.html', context)





# View function to import patients from an uploaded Excel file
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
                
                
                # Calculate the patient's score based on the data in the Excel file
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


# View function to edit an existing patient data
def edit_patient(request, id):
    if 'user_id' not in request.session:
        messages.error(request, "Please log in before accessing this site !.")
        return redirect('login')
    
    patient = models.Patient.objects.get(id=id)
    print(id)
    if request.method == 'POST':

        old_values = {
            'full_name': patient.full_name,
            'email': patient.email,
            'address': patient.address,
            'phone': patient.phone,
            'urgency_level': patient.urgency_level,
            'age': patient.age,
            'gender': patient.gender,
            'action': patient.action
        }

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
        user = Users.objects.get(id=request.session["user_id"])
        patient.save()
        for field, old_value in old_values.items():
            new_value = getattr(patient, field)
            if old_value != new_value:
                models.EditLog.objects.create(
                    user=user,  # Assuming the user is logged in
                    edit_time=timezone.now(),
                    edited_field=field,
                    old_value=str(old_value),
                    new_value=str(new_value)
                )
        messages.success(request, f'Patient {patient.full_name} updated successfully!')
        return redirect('../../dash')
    
    genders = models.Gender.objects.all()
    actions = models.Action.objects.all()
    urgency_levels = models.UrgencyLevel.objects.all()
    statuses = models.Status.objects.all()
    
    context = {
        'genders': genders,
        'actions': actions,
        'urgency_levels': urgency_levels,
        'statuses': statuses,
        'patient' : patient
    }

    return render(request, 'pages/edit_patient.html', context)


# View function to delete a patient based on their ID
def delete_patient(request, id):
    patient = models.Patient.objects.get(id=id)
    
    if request.method == 'POST':
        user = Users.objects.get(id=request.session["user_id"])
        models.DeleteLog.objects.create(
            user=user,  # Assuming the user is logged in
            delete_time=timezone.now(),
            patient_name=patient.full_name
        )
        patient.delete()
        messages.success(request, f'Patient {patient.full_name} deleted successfully!')
        return redirect('/pages/dash')
    
# View function to view the users information
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
    

#Function to create a user
def create_user(id,fname, lname, email, passwd, phone):
    enc_pass = make_password(passwd)
    new_user = models.Users.objects.create(
        first_name=fname,
        last_name=lname,
        email=email,
        phone=phone,
        password=enc_pass,
        id=id
    )
    return new_user


#Function to activate the email of the user
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


def admin_dashbord(request):
    if request.method == 'POST':
        if 'password' in request.POST:
            # Check the password
            password = request.POST.get('password')
            if password == 'admin123':
                # Password is correct, mark user as authenticated
                request.session['authenticated'] = True
                return render(request, 'pages/admin_dashbord.html', {
                    'authenticated': True
                })
            else:
                messages.error(request, 'Invalid password.')
    else:
        # If GET request, reset authentication
        request.session['authenticated'] = False

    return render(request, 'pages/admin_dashbord.html', {
        'authenticated': request.session.get('authenticated', False)
    })



def manage_genders(request):
    if request.method == 'POST':
        gender_name = request.POST.get('gender_name')
        if gender_name:
            models.Gender.objects.create(name=gender_name)
            messages.success(request, 'Gender added successfully.')
        else:
            messages.error(request, 'Gender name cannot be empty.')
    return redirect('admin_dashbord')



def manage_actions(request):
    action_name = request.POST.get('action_name')
    if action_name:
        models.Action.objects.create(name=action_name)
        messages.success(request, 'Action added successfully.')
    return redirect('admin_dashbord')



def manage_urgency_levels(request):
    urgency_name = request.POST.get('urgency_name')
    if urgency_name:
        models.UrgencyLevel.objects.create(name=urgency_name)
        messages.success(request, 'Urgency level added successfully.')
    return redirect('admin_dashbord')

def manage_stauts(request):
    stauts_name = request.POST.get('stauts_name')
    if stauts_name:
        models.Status.objects.create(name=stauts_name)
        messages.success(request, ' stauts added successfully.')
    return redirect('admin_dashbord')



def create_score_visualization(patients):
    # Extract data
    names = [patient.name for patient in patients]
    scores = [patient.score for patient in patients]

    # Create bar chart
    plt.figure(figsize=(10, 6))
    plt.bar(names, scores, color='blue')
    plt.xlabel('Patient Name')
    plt.ylabel('Score')
    plt.title('Patient Scores')
    plt.xticks(rotation=45, ha='right')

    # Save the plot to a BytesIO object
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    
    # Optionally, you can return the buffer or save the image in the filesystem
    return buffer
