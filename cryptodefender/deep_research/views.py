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

    suspicious_found = []
    cpu_cores = psutil.cpu_count(logical=True)

    # 🔥 PRIME CPU USAGE (VERY IMPORTANT)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except:
            pass

    # small delay for real measurement
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

            processes.append((name, cpu_normalized))

            # detect suspicious only (optional logic)
            if any(m in name for m in suspicious_names):
                suspicious_found.append(f"⚠️ Miner: {name}")

        except:
            continue

    # sort top 5
    top = sorted(processes, key=lambda x: x[1], reverse=True)[:5]

    result = []
    for name, cpu in top:
        result.append(f"{name} ({cpu}%)")

    if not result:
        result = ["No active processes found"]

    return {
        "status": "✅ System Safe",
        "details": result
    }



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

    # default waiting state
    parsed_result = None

    if latest and latest.result:
        try:
            parsed_result = json.loads(latest.result)
        except:
            parsed_result = None

    return render(request, 'core/deep_research.html', {
        'result': parsed_result
    })


