from django.shortcuts import render, redirect
import psutil
import time
import pyotp
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required


def home(request):
    return render(request, 'core/home.html')


def detect(request):
    if request.method == "POST":

        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('C:\\').percent   # Windows fix

        # 🔹 Network usage
        net1 = psutil.net_io_counters()
        time.sleep(1)
        net2 = psutil.net_io_counters()

        upload_speed = (net2.bytes_sent - net1.bytes_sent) / 1024
        download_speed = (net2.bytes_recv - net1.bytes_recv) / 1024

        # 🔥 Detection logic
        if cpu > 30 and ram > 90 and disk > 70 and download_speed > 500:
            result = "⚠️ Mining / Suspicious Activity Detected"
        else:
            result = "✅ System Safe"

        context = {
            'cpu': cpu,
            'ram': ram,
            'disk': disk,
            'upload': round(upload_speed, 2),
            'download': round(download_speed, 2),
            'result': result
        }

        return render(request, 'core/result.html', context)

    return render(request, 'core/home.html')



# temp storage
signup_data = {}
otp_storage = {}


# 🔹 SIGNUP (send OTP)
def signup_view(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        # store data temporarily
        signup_data[email] = {
            'username': username,
            'password': password
        }

        # generate OTP
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otp = totp.now()

        otp_storage[email] = otp

        # send email
        send_mail(
            'Your Signup OTP',
            f'Your OTP is {otp}',
            'your_email@gmail.com',
            [email],
            fail_silently=False,
        )

        request.session['email'] = email
        return redirect('verify_signup_otp')

    return render(request, 'core/signup.html')


# 🔹 VERIFY SIGNUP OTP
def verify_signup_otp(request):
    if request.method == "POST":
        entered_otp = request.POST['otp']
        email = request.session.get('email')

        if otp_storage.get(email) == entered_otp:
            data = signup_data.get(email)

            # create user AFTER verification
            User.objects.create_user(
                username=data['username'],
                email=email,
                password=data['password']
            )

            return redirect('login')

    return render(request, 'core/verify_otp.html')


# 🔹 LOGIN (normal login)
def login_view(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user:
            login(request, user)
            return redirect('home')

    return render(request, 'core/home_loggedin.html')


@login_required
def home_loggedin(request):
    return render(request, 'core/home_loggedin.html')

def logout_view(request):
    logout(request)
    return redirect('home')