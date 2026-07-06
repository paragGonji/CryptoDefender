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






@login_required
def admin_dashboard(request):
    if not is_admin(request.user):
        logout(request)
        return redirect('admin_login')

    # 🔥 HANDLE ACTIONS
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "remove":
            user_id = request.POST.get("user_id")

            if user_id and int(user_id) != request.user.id:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM admin_access WHERE user_id = %s",
                        [user_id]
                    )

        elif action == "delete_user":
            user_id = request.POST.get("user_id")

            if user_id and int(user_id) != request.user.id:
                try:
                    user_to_delete = User.objects.get(id=user_id)
                    
                    # First remove from admin_access if they're an admin
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM admin_access WHERE user_id = %s",
                            [user_id]
                        )
                    
                    # Then delete the user
                    user_to_delete.delete()
                    
                except User.DoesNotExist:
                    pass  # User doesn't exist

        return redirect('admin_dashboard')

    # 🔽 GET ALL USERS
    users = User.objects.all()

    # 🔽 GET ADMIN IDS
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id FROM admin_access")
        admin_ids = [row[0] for row in cursor.fetchall()]

    return render(request, 'accounts/admin_dashboard.html', {
        'users': users,
        'admin_ids': admin_ids
    })





# 👑 ADMIN MANAGEMENT PAGE
@login_required
def manage_admins(request):
    if not is_admin(request.user):
        logout(request)
        return redirect('admin_login')

    if request.method == "POST":
        action = request.POST.get("action")

        if action == "create_admin":
            username = request.POST.get("username")
            password = request.POST.get("password")

            if username and password:
                user, created = User.objects.get_or_create(username=username)
                user.set_password(password)
                user.save()

                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO admin_access (user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                        [user.id]
                    )

        elif action == "remove":
            user_id = request.POST.get("user_id")

            if user_id and int(user_id) != request.user.id:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM admin_access WHERE user_id = %s",
                        [user_id]
                    )

        # 🔥 IMPORTANT LINE
        return redirect('manage_admins')

    # 🔽 ALWAYS LOAD FRESH DATA AFTER REDIRECT
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id FROM admin_access")
        admin_ids = [row[0] for row in cursor.fetchall()]

    users = User.objects.filter(id__in=admin_ids)

    return render(request, 'accounts/manage_admins.html', {
        'users': users
    })




# 🚪 LOGOUT (optional if not already)
def admin_logout(request):
    logout(request)
    return redirect('admin_login')