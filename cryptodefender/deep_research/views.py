from django.shortcuts import render, redirect
import psutil
from core.models import ScanResult


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





def deep_research(request):
    latest = ScanResult.objects.last()   # get latest scan

    return render(request, 'core/deep_research.html', {
        'result': latest.result if latest else None
    })