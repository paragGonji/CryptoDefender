from urllib import request

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

from collections import deque

from .ml.prediction import predict_mining

metric_history = deque(maxlen=20)

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
        if cpu > 90 and ram > 90 and disk > 70 and download_speed > 500:
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
# 🔹 LOGIN (Username OR Email)
def login_view(request):
    if request.method == "POST":
        username_or_email = request.POST['username']
        password = request.POST['password']

        # First try username
        user = authenticate(
            request,
            username=username_or_email,
            password=password
        )

        # If username login fails, try email
        if user is None:
            try:
                user_obj = User.objects.get(email=username_or_email)
                user = authenticate(
                    request,
                    username=user_obj.username,
                    password=password
                )
            except User.DoesNotExist:
                user = None

        if user is not None:
            login(request, user)
            return redirect('home_loggedin')

        return render(request, 'core/login.html', {
            'error': 'Invalid username or password'
        })

    return render(request, 'core/login.html')


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
# 🏠 Home (Logged In)
@login_required
def home_loggedin(request):

    context = {
        "model_accuracy": 96.94
    }

    if request.method == "POST":

        print("\n" + "=" * 60)
        print("🚀 LSTM CRYPTOJACKING DETECTION STARTED")
        print("=" * 60)

        samples = []

        # ==================================================
        # INITIAL NETWORK COUNTERS
        # ==================================================

        print("🌐 Initializing network counters...")

        net_before = psutil.net_io_counters()

        last_sent = net_before.bytes_sent
        last_recv = net_before.bytes_recv

        # ==================================================
        # COLLECT 20 SAMPLES
        # ==================================================

        print("📊 Collecting data...")
        print("Required samples: 20")

        for i in range(20):

            sample_number = i + 1

            print(
                f"📥 Collecting data... "
                f"Sample {sample_number}/20"
            )

            # ==================================================
            # CPU
            # ==================================================

            cpu_total = psutil.cpu_percent(
                interval=0.2
            )

            cpu_times = psutil.cpu_times_percent(
                interval=0.1
            )

            cpu_user = getattr(
                cpu_times,
                "user",
                0
            )

            cpu_system = getattr(
                cpu_times,
                "system",
                0
            )

            cpu_idle = getattr(
                cpu_times,
                "idle",
                0
            )

            cpu_iowait = getattr(
                cpu_times,
                "iowait",
                0
            )

            # ==================================================
            # MEMORY
            # ==================================================

            memory = psutil.virtual_memory()

            mem_percent = memory.percent
            mem_used = memory.used
            mem_available = memory.available

            # ==================================================
            # PROCESS INFORMATION
            # ==================================================

            processcount_running = 0
            processcount_sleeping = 0
            processcount_thread = 0
            processcount_total = 0

            for process in psutil.process_iter(
                ["status", "num_threads"]
            ):

                try:

                    processcount_total += 1

                    status = process.info.get(
                        "status"
                    )

                    if status == psutil.STATUS_RUNNING:

                        processcount_running += 1

                    elif status == psutil.STATUS_SLEEPING:

                        processcount_sleeping += 1

                    processcount_thread += (
                        process.info.get(
                            "num_threads"
                        ) or 0
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):

                    pass

            # ==================================================
            # NETWORK
            # ==================================================

            net_now = psutil.net_io_counters()

            upload_bytes = (
                net_now.bytes_sent -
                last_sent
            )

            download_bytes = (
                net_now.bytes_recv -
                last_recv
            )

            last_sent = net_now.bytes_sent
            last_recv = net_now.bytes_recv

            network_lo_tx = (
                max(upload_bytes, 0) / 1024
            )

            network_lo_rx = (
                max(download_bytes, 0) / 1024
            )

            # ==================================================
            # CREATE SAMPLE
            # ==================================================

            sample = {

                "cpu_total": cpu_total,

                "cpu_user": cpu_user,

                "cpu_system": cpu_system,

                "cpu_idle": cpu_idle,

                "cpu_iowait": cpu_iowait,

                "mem_percent": mem_percent,

                "mem_used": mem_used,

                "mem_available": mem_available,

                "processcount_running":
                    processcount_running,

                "processcount_sleeping":
                    processcount_sleeping,

                "processcount_thread":
                    processcount_thread,

                "processcount_total":
                    processcount_total,

                "network_lo_rx":
                    network_lo_rx,

                "network_lo_tx":
                    network_lo_tx
            }

            samples.append(sample)

            print(
                f"   ✓ Sample {sample_number}/20 collected | "
                f"CPU: {cpu_total:.2f}% | "
                f"RAM: {mem_percent:.2f}% | "
                f"Processes: {processcount_total}"
            )

            # ==================================================
            # WAIT BEFORE NEXT SAMPLE
            # ==================================================

            if i < 19:

                time.sleep(0.25)

        # ==================================================
        # DATA COLLECTION COMPLETE
        # ==================================================

        print("\n" + "-" * 60)

        print(
            f"✅ Data collection complete: "
            f"{len(samples)}/20 samples"
        )

        print("-" * 60)

        # ==================================================
        # FINAL PREDICTION
        # ==================================================

        print("🤖 Running PyTorch LSTM prediction...")

        prediction = predict_mining(
            samples
        )

        print(
            f"✅ LSTM prediction complete"
        )

        print(
            f"Prediction: "
            f"{prediction['prediction_label']}"
        )

        print(
            f"Threat Score: "
            f"{prediction['threat_score']:.2f}%"
        )

        print(
            f"Raw Probability: "
            f"{prediction.get('raw_score', 0):.4f}"
        )

        print(
            f"Model Accuracy: "
            f"{prediction['accuracy']:.2f}%"
        )

        # ==================================================
        # CURRENT METRICS
        # ==================================================

        latest = samples[-1]

        cpu = round(
            latest["cpu_total"],
            2
        )

        ram = round(
            latest["mem_percent"],
            2
        )

        disk = psutil.disk_usage(
            "/"
        ).percent

        upload = round(
            latest["network_lo_tx"],
            2
        )

        download = round(
            latest["network_lo_rx"],
            2
        )

        process_count = int(
            latest["processcount_total"]
        )

        # ==================================================
        # TOP 5 DATA
        # ==================================================

        top_cpu = sorted(
            samples,
            key=lambda x: x["cpu_total"],
            reverse=True
        )[:5]

        top_ram = sorted(
            samples,
            key=lambda x: x["mem_percent"],
            reverse=True
        )[:5]

        # ==================================================
        # DISK
        # ==================================================

        disk_samples = []

        for sample in samples:

            disk_value = psutil.disk_usage(
                "/"
            ).percent

            disk_samples.append({

                "value": disk_value

            })

        top_disk = sorted(
            disk_samples,
            key=lambda x: x["value"],
            reverse=True
        )[:5]

        # ==================================================
        # NETWORK
        # ==================================================

        top_upload = sorted(
            samples,
            key=lambda x: x["network_lo_tx"],
            reverse=True
        )[:5]

        top_download = sorted(
            samples,
            key=lambda x: x["network_lo_rx"],
            reverse=True
        )[:5]

        # ==================================================
        # PROCESS
        # ==================================================

        top_process = sorted(
            samples,
            key=lambda x: x["processcount_total"],
            reverse=True
        )[:5]

        # ==================================================
        # CONTEXT
        # ==================================================

        context.update({

            "cpu": cpu,

            "ram": ram,

            "disk": disk,

            "upload": upload,

            "download": download,

            "process_count":
                process_count,

            "samples": 20,

            "prediction_label":
                prediction["prediction_label"],

            "threat_score":
                prediction["threat_score"],

            "model_accuracy":
                prediction["accuracy"],

            "top_cpu":
                top_cpu,

            "top_ram":
                top_ram,

            "top_disk":
                top_disk,

            "top_upload":
                top_upload,

            "top_download":
                top_download,

            "top_process":
                top_process,

            "analysis_complete": True,

        })

        # ==================================================
        # FINISHED
        # ==================================================

        print("=" * 60)

        print("🏁 DETECTION FINISHED")

        print(
            f"Final Result: "
            f"{prediction['prediction_label']}"
        )

        print(
            f"Final Threat Score: "
            f"{prediction['threat_score']:.2f}%"
        )

        print("=" * 60 + "\n")

    return render(
        request,
        "core/home_loggedin.html",
        context
    )






def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('home')   # ✅ go to login page (better UX)








def analyze_processes(processes):
    suspicious_names = ["xmrig", "minerd", "cpuminer"]

    # ❌ Processes to IGNORE
    ignore_list = [
        "system idle process",
        "system",
        "system interrupts",
        "desktopextension.exe",
        "windows_scanner.exe"
    ]

    # 🔽 Sort by CPU usage
    sorted_processes = sorted(
        processes,
        key=lambda x: x.get("cpu", 0),
        reverse=True
    )

    top5 = []
    detected_miners = []

    for p in sorted_processes:
        name = (p.get("name") or "").lower()
        cpu = p.get("cpu", 0)

        # ❌ IGNORE unwanted processes
        if any(ignore in name for ignore in ignore_list):
            continue

        # ✅ Add to list
        top5.append(f"{name} ({cpu:.1f}%)")

        # 🔴 Detect miners
        if any(m in name for m in suspicious_names):
            detected_miners.append(name)

        # Stop at 5
        if len(top5) == 5:
            break

    # 🚨 RESULT
    if detected_miners:
        return {
            "status": "⚠️ Suspicious Activity Detected",
            "type": "miner_found",
            "miners": detected_miners,
            "top5": top5
        }
    else:
        return {
            "status": "✅ System Safe",
            "type": "high_usage",
            "top5": top5
        }


#api

@csrf_exempt
def receive_scan(request):
    if request.method == "POST":
        data = json.loads(request.body)

        processes = data.get("processes", [])

        result_data = analyze_processes(processes)

        # ✅ Save FULL JSON (not string text)
        ScanResult.objects.create(
            result=json.dumps(result_data)
        )

        return JsonResponse({"status": "saved"})

    return JsonResponse({"error": "invalid"}, status=400)





@login_required
def profile_view(request):

    return render(request, 'core/profile.html')