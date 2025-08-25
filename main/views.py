from django.shortcuts import render , redirect
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import TranscriptsDisabled, NoTranscriptFound, VideoUnavailable
import re
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.decorators import login_required
def reg(request):
    if request.user.is_authenticated:
        return redirect('home')  # Already logged in

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
        else:
            try:
                # Validate password strength
                validate_password(password1)
                
                # Create user
                user = User.objects.create_user(username=username, email=email, password=password1)
                user.save()

                messages.success(request, "User registered successfully!")
                return redirect('login')  # Or wherever you want to redirect after register

            except ValidationError as e:
                messages.error(request, e.messages)
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

    return render(request, 'reg.html')
def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')  # already logged in

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')
@login_required(login_url='login')
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return redirect('login')
    else:
        return redirect('home')

def index(request):
   
    return render(request, 'index.html')


def extract_video_id(url):
    regex = r'(?:youtu\.be/|youtube\.com/(?:embed/|v/|watch\?v=|watch\?.+&v=))([0-9A-Za-z_-]{11})'
    match = re.search(regex, url)
    return match.group(1) if match else None

@login_required(login_url='login')
def home(request):
    # your existing home logic (transcript viewer etc) goes here
proxies = {
    'http': 'http://103.216.82.38:6667',
    'https': 'http://103.216.82.38:6667',
}


    context = {'transcript': None, 'error': None}

    if request.method == 'POST':
        url = request.POST.get('youtube_url', '')
        video_id = extract_video_id(url)

        if not video_id:
            context['error'] = "Invalid YouTube URL."
        else:
            try:
                #transcript = YouTubeTranscriptApi().fetch(video_id)
               transcript = YouTubeTranscriptApi(proxies=proxies).fetch(video_id)

                formatted = [f"[{line.start:.2f}s] {line.text}" for line in transcript]
                context['transcript'] = "\n".join(formatted)
            except Exception as e:
                context['error'] = f"Error: {str(e)}"

    return render(request, 'home.html', context)



    def setting(request):
   
        return render(request, 'setting.html')

