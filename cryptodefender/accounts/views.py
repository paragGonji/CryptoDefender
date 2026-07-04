from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db import connection


# 🔐 CHECK ADMIN (PostgreSQL table)
def is_admin(user):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT 1 FROM admin_access WHERE user_id = %s",
            [user.id]
        )
        return cursor.fetchone() is not None


# 🔐 ADMIN LOGIN
def admin_login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)

        if user and is_admin(user):
            login(request, user)
            return redirect('admin_dashboard')
        else:
            return render(request, 'accounts/admin_login.html', {
                'error': 'Invalid admin credentials'
            })

    return render(request, 'accounts/admin_login.html')


# 📊 GLOBAL PAGE (USER LIST + SEARCH)
@login_required
def admin_dashboard(request):
    if not is_admin(request.user):
        return redirect('home')

    query = request.GET.get('q')

    if query:
        users = User.objects.filter(username__icontains=query)
    else:
        users = User.objects.all()

    return render(request, 'accounts/admin_dashboard.html', {
        'users': users
    })


# 👑 ADMIN MANAGEMENT PAGE
@login_required
def manage_admins(request):
    if not is_admin(request.user):
        return redirect('home')

    users = User.objects.all()

    if request.method == "POST":
        user_id = request.POST.get("user_id")
        action = request.POST.get("action")

        with connection.cursor() as cursor:
            if action == "add":
                cursor.execute(
                    "INSERT INTO admin_access (user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                    [user_id]
                )
            elif action == "remove":
                cursor.execute(
                    "DELETE FROM admin_access WHERE user_id = %s",
                    [user_id]
                )

    return render(request, 'accounts/manage_admins.html', {
        'users': users
    })


# 🚪 LOGOUT (optional if not already)
def admin_logout(request):
    logout(request)
    return redirect('admin_login')