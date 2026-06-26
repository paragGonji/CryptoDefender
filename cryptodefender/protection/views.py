
from django.shortcuts import render

def protection(request):
    return render(request, 'core/protection.html')