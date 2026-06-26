from django.shortcuts import render

def prevent_guide(request):
    return render(request, 'core/prevent_guide.html')
