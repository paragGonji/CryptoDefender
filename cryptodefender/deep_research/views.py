from django.shortcuts import render, redirect
import psutil
from core.models import ScanResult
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render


# Global storage
latest_result = {
    "status": "Waiting for scan...",
    "details": []
}




# 🧠 Detection Function
def detect_mining_process():
    suspicious_names = ["xmrig", "minerd", "cpuminer"]
    safe_processes = ["explorer.exe", "chrome.exe", "python.exe"]

    suspicious_found = []

    for proc in psutil.process_iter(['name', 'cpu_percent']):
        try:
            name = (proc.info['name'] or "").lower()
            cpu = proc.info['cpu_percent']

            # 🔴 Known miners
            if any(miner in name for miner in suspicious_names):
                suspicious_found.append(f"⚠️ Known Miner Detected: {name}")

            # 🔴 High CPU usage
            elif cpu and cpu > 50:
                suspicious_found.append(f"⚠️ High CPU Usage: {name} ({cpu}%)")

            # 🔴 Unknown EXE
            elif name.endswith(".exe") and name not in safe_processes:
                suspicious_found.append(f"⚠️ Unknown EXE: {name}")

        except:
            pass

    if suspicious_found:
        return suspicious_found
    return ["✅ System Safe"]


# 🔷 Your existing view upgraded
# def deep_research(request):

#     if request.method == "POST":
#         result = detect_mining_process()

#         # 💾 Store in session
#         request.session['scan_result'] = result

#         return redirect('deep_research')

#     # 📦 Get result from session
#     result = request.session.get('scan_result', None)

#     return render(request, 'core/deep_research.html', {'result': result})


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

    detected = []
    risk_score = 0

    for p in processes:
        name = (p.get("name") or "").lower()
        cpu = p.get("cpu", 0)
        mem = p.get("memory", 0)

        # Ignore system processes
        if "idle" in name or "system" in name:
            continue

        # Rule 1: Known miners
        if any(s in name for s in suspicious_names):
            detected.append(f"🚨 Known Miner: {name}")
            risk_score += 80

        # Rule 2: High CPU + low memory
        elif cpu > 60 and mem < 10:
            detected.append(f"⚠️ Suspicious CPU Spike: {name} ({cpu:.1f}%)")
            risk_score += 40

        # Rule 3: Medium suspicious
        elif cpu > 40:
            detected.append(f"⚠️ High CPU: {name} ({cpu:.1f}%)")
            risk_score += 20

    # Final decision
    if risk_score > 70:
        status = "⚠️ Mining Activity Detected!"
    elif risk_score > 30:
        status = "⚠️ Suspicious Activity"
    else:
        status = "✅ SAFE"

    if not detected:
        detected.append("No suspicious process found")

    return {
        "status": status,
        "details": detected
    }






def deep_research(request):
    latest = ScanResult.objects.last()

    parsed_result = None

    if latest:
        try:
            parsed_result = json.loads(latest.result)
        except:
            parsed_result = None

    return render(request, 'core/deep_research.html', {
        'result': parsed_result
    })

