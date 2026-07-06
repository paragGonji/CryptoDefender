from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.contrib import messages
from django.db.models import Q

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

    # 🔥 GET ADMIN IDS - ALWAYS FETCH FRESH
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id FROM admin_access")
        admin_ids = [row[0] for row in cursor.fetchall()]

    # 🔥 HANDLE POST ACTIONS
    if request.method == "POST":
        action = request.POST.get("action")
        user_id = request.POST.get("user_id")

        if action == "delete_user":
            if user_id and int(user_id) != request.user.id:
                try:
                    user_to_delete = User.objects.get(id=user_id)
                    username = user_to_delete.username
                    
                    # Check if user is admin before deleting
                    if user_to_delete.id in admin_ids:
                        messages.error(request, f"Cannot delete admin user. Remove admin privileges first.")
                    else:
                        user_to_delete.delete()
                        messages.success(request, f"User '{username}' deleted successfully.")
                except User.DoesNotExist:
                    messages.error(request, "User not found.")
            else:
                messages.error(request, "You cannot delete your own account.")
        
        elif action == "make_admin":
            if user_id and int(user_id) != request.user.id:
                try:
                    user = User.objects.get(id=user_id)
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "INSERT INTO admin_access (user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                            [user_id]
                        )
                    messages.success(request, f"User '{user.username}' is now an admin.")
                except User.DoesNotExist:
                    messages.error(request, "User not found.")
            else:
                messages.error(request, "You cannot change your own role.")

        return redirect('admin_dashboard')

    # 🔽 GET SEARCH QUERY
    search_query = request.GET.get('search', '').strip()
    
    # 🔽 GET ONLY REGULAR USERS (NOT ADMINS)
    if search_query:
        # Search with query
        users = User.objects.filter(
            Q(username__icontains=search_query) | 
            Q(email__icontains=search_query)
        ).exclude(id__in=admin_ids)
    else:
        # Get all non-admin users
        users = User.objects.exclude(id__in=admin_ids)

    return render(request, 'accounts/admin_dashboard.html', {
        'users': users,
        'admin_ids': admin_ids,
        'search_query': search_query
    })


# 👑 ADMIN MANAGEMENT PAGE
@login_required
def manage_admins(request):
    if not is_admin(request.user):
        logout(request)
        return redirect('admin_login')

    # 🔥 HANDLE POST ACTIONS
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "create_admin":
            username = request.POST.get("username")
            password = request.POST.get("password")

            if username and password:
                try:
                    # Check if user already exists
                    user, created = User.objects.get_or_create(username=username)
                    if created:
                        user.set_password(password)
                        user.save()
                        messages.success(request, f"Admin '{username}' created successfully.")
                    else:
                        # User exists, just make them admin
                        messages.info(request, f"User '{username}' already exists. Added as admin.")
                    
                    # Add to admin_access table
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "INSERT INTO admin_access (user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                            [user.id]
                        )
                except Exception as e:
                    messages.error(request, f"Error creating admin: {str(e)}")

        elif action == "remove_admin":
            user_id = request.POST.get("user_id")
            if user_id and int(user_id) != request.user.id:
                try:
                    # ONLY remove from admin_access - user stays in database
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM admin_access WHERE user_id = %s",
                            [user_id]
                        )
                    messages.success(request, "Admin privileges removed successfully. User is now a regular user.")
                except Exception as e:
                    messages.error(request, f"Error removing admin: {str(e)}")
            else:
                messages.error(request, "You cannot remove your own admin privileges.")

        elif action == "delete_admin_user":
            user_id = request.POST.get("user_id")
            if user_id and int(user_id) != request.user.id:
                try:
                    # First remove from admin_access
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM admin_access WHERE user_id = %s",
                            [user_id]
                        )
                    
                    # Then delete the user completely
                    user_to_delete = User.objects.get(id=user_id)
                    username = user_to_delete.username
                    user_to_delete.delete()
                    
                    messages.success(request, f"Admin user '{username}' has been permanently deleted.")
                except User.DoesNotExist:
                    messages.error(request, "User not found.")
                except Exception as e:
                    messages.error(request, f"Error deleting admin: {str(e)}")
            else:
                messages.error(request, "You cannot delete your own account.")

        return redirect('manage_admins')

    # 🔽 GET ADMIN IDS - ALWAYS FETCH FRESH
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id FROM admin_access")
        admin_ids = [row[0] for row in cursor.fetchall()]

    # 🔽 GET ALL ADMIN USERS
    users = User.objects.filter(id__in=admin_ids)

    return render(request, 'accounts/manage_admins.html', {
        'users': users,
        'admin_ids': admin_ids
    })


# 🚪 LOGOUT
def admin_logout(request):
    logout(request)
    return redirect('admin_login')