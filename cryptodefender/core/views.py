from django.shortcuts import render, redirect
import psutil
import time
import pyotp
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required


from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
from .models import ScanResult


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

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home_loggedin')   # ✅ go to logged-in dashboard
        else:
            return render(request, 'core/login.html', {
                'error': 'Invalid username or password'
            })

    return render(request, 'core/login.html')   # ✅ ALWAYS show login page



# 🔍 Mining Detection Function
def detect_mining():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    if cpu > 70 and ram > 80:
        status = "⚠️ Crypto Mining Detected!"
    else:
        status = "✅ System Safe"

    return status, cpu, ram, disk


# 🏠 Home (Logged In)
@login_required
def home_loggedin(request):
    context = {}

    if request.method == "POST":

        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('C:\\').percent  # Windows

        # Network usage
        net1 = psutil.net_io_counters()
        time.sleep(1)
        net2 = psutil.net_io_counters()

        upload_speed = (net2.bytes_sent - net1.bytes_sent) / 1024
        download_speed = (net2.bytes_recv - net1.bytes_recv) / 1024

        # Detection logic (same as your function)
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

    return render(request, 'core/home_loggedin.html', context)


def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('home')   # ✅ go to login page (better UX)


#api


@csrf_exempt
def receive_scan(request):
    if request.method == "POST":
        data = json.loads(request.body)
        result_list = data.get("result", [])

        # Convert list to string
        result_text = "\n".join(result_list)

        ScanResult.objects.create(result=result_text)

        return JsonResponse({"status": "saved"})

    return JsonResponse({"error": "invalid"}, status=400)