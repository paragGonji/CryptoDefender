
# Create your views here.
from django.shortcuts import render

def deep_research(request):
    return render(request, 'core/deep_research.html')