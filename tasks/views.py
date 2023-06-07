from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordResetForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordResetForm

# Para la recuperacion del password
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string

# Create your views here.
def home(request):
    return render(request, 'home.html')

def signup(request):

    if request.method=='GET':
        return render(request, 'signup.html', {
            'form': UserCreationForm
        })
    else:
        if request.POST['password1'] ==  request.POST['password2']:
            # register user
            try:
                user = User.objects.create_user(username=request.POST['username'], password=request.POST['password1'], email=request.POST['email'])
                user.save()
                login(request, user)
                return redirect(tasks)
            except IntegrityError:
                return render(request, 'signup.html', {
                    'form': UserCreationForm,
                    'error': 'Username already exists'
                })
        return render(request, 'signup.html', {
            'form': UserCreationForm,
            'error': 'Password do not match'
        })

@login_required
def tasks(request):
    return render(request, 'tasks.html')

def signout(request):
    logout(request)
    return redirect(home)

def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'form': AuthenticationForm
        })
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])

        if user is None:

            return render(request, 'signin.html', {
                'form': AuthenticationForm,
                'error': 'Username or password incorrect'
            })
        else:
            login(request, user)
            return redirect('tasks')
        
def resetpwd(request):
    if request.method == 'GET':
        return render(request, 'resetpwd.html',{
            'form': PasswordResetForm
        })
    else:
        username = request.POST['username']
        try:
            user = User.objects.get(username=username)
            print('El usuario si existe: ', user.email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_url=f'http://localhost:3000/signin/accounts/reset/{uid}/{token}/'
            message = render_to_string('email/reset_password.html', {
                'reset_url': reset_url,
                'username': user.username
            })

            send_mail('Reset your password', message,'garapower26@gmail.com', [user.email] )

            return render(request, 'resetpwd.html',{
                'succesfull': 'Email recuperation is sending. Please check your email for further details'
            })
        except User.DoesNotExist:
            return render(request, 'resetpwd.html',{
                'error': 'Username does not exists, try again'
            })  
