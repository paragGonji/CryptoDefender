from django.shortcuts import render

def logs_monitoring(request):
    return render(request, "core/logs_monitoring.html")
