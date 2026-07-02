from django.shortcuts import render, redirect
import psutil
from core.models import ScanResult
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta

# Global storage
latest_result = {
    "status": "Waiting for scan...",
    "details": []
}




# 🧠 Detection Function
def detect_mining_process():
    suspicious_names = ["xmrig", "minerd", "cpuminer"]

    # ✅ IGNORE LIST
    ignore_list = [
        "windowsterminal.exe",
        "chrome.exe",
        "explorer.exe",
        "dwm.exe",
        "system"
    ]

    suspicious_found = []
    cpu_cores = psutil.cpu_count(logical=True)

    # 🔥 PRIME CPU USAGE
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except:
            pass

    import time
    time.sleep(0.5)

    processes = []

    for proc in psutil.process_iter(['name']):
        try:
            name = (proc.info['name'] or "").lower()

            cpu = proc.cpu_percent(None)
            cpu_normalized = round(cpu / cpu_cores, 1)

            if not name:
                continue

            # ✅ FULL IGNORE (REMOVED FROM EVERYTHING)
            if name in ignore_list:
                continue

            processes.append((name, cpu_normalized))

            # 🚨 Known miners
            if any(m in name for m in suspicious_names):
                suspicious_found.append(f"⚠️ Miner: {name}")

            # ⚠️ Unknown EXE
            elif name.endswith(".exe"):
                suspicious_found.append(f"⚠️ Unknown EXE: {name}")

        except:
            continue

    # 🔝 Top 5 processes (AFTER IGNORE)
    top = sorted(processes, key=lambda x: x[1], reverse=True)[:5]

    result = [f"{name} ({cpu}%)" for name, cpu in top]

    if not result:
        result = ["No active processes found"]

    return {
        "status": "✅ System Safe",
        "details": result
    }





@csrf_exempt
def scan_result(request):
    global latest_result

    if request.method == "POST":
        data = json.loads(request.body)
        processes = data.get("processes", [])

        latest_result = analyze_processes(processes)

        return JsonResponse({"message": "Data received"})

    return JsonResponse({"error": "Invalid request"})








def analyze_processes(processes):
    suspicious_names = ["xmrig", "minerd", "cpuminer"]

    # ✅ SAME IGNORE LIST HERE
    ignore_list = [
        "windowsterminal.exe",
        "chrome.exe",
        "explorer.exe",
        "dwm.exe",
        "system",
        "wmiprvse.exe"
    ]

    detected = []
    clean_processes = []
    risk_score = 0

    for p in processes:
        name = (p.get("name") or "").lower()
        cpu = p.get("cpu", 0)
        mem = p.get("memory", 0)

        if not name:
            continue

        # ✅ FULL IGNORE (REMOVE COMPLETELY)
        if name in ignore_list:
            continue

        clean_processes.append((name, cpu))

        # 🚨 Known miners
        if any(s in name for s in suspicious_names):
            detected.append(f"🚨 Known Miner: {name}")
            risk_score += 80

        # ⚠️ High CPU + low memory
        elif cpu > 60 and mem < 10:
            detected.append(f"⚠️ Suspicious CPU Spike: {name} ({cpu:.1f}%)")
            risk_score += 40

        # ⚠️ Medium CPU
        elif cpu > 40:
            detected.append(f"⚠️ High CPU: {name} ({cpu:.1f}%)")
            risk_score += 20

    # 🔝 Top 5 AFTER IGNORE
    top = sorted(clean_processes, key=lambda x: x[1], reverse=True)[:5]

    result = [f"{name} ({cpu:.1f}%)" for name, cpu in top]

    if not result:
        result = ["No active processes found"]

    # ✅ FINAL STATUS
    if risk_score > 70:
        status = "⚠️ Mining Activity Detected!"
    elif risk_score > 30:
        status = "⚠️ Suspicious Activity"
    else:
        status = "✅ System Safe"

    return {
        "status": status,
        "details": result
    }





def deep_research(request):
    latest = ScanResult.objects.last()

    parsed_result = None

    if latest:
        # ✅ DELETE if older than 5 minutes
        if timezone.now() - latest.created_at > timedelta(minutes=5):
            latest.delete()
        else:
            try:
                parsed_result = json.loads(latest.result)
            except:
                parsed_result = None

    return render(request, 'core/deep_research.html', {
        'result': parsed_result
    })




# def deep_research(request):
#     latest = ScanResult.objects.last()

#     # default waiting state
#     parsed_result = None

#     if latest and latest.result:
#         try:
#             parsed_result = json.loads(latest.result)
#         except:
#             parsed_result = None

#     return render(request, 'core/deep_research.html', {
#         'result': parsed_result
#     })


