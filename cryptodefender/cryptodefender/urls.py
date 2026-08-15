"""
URL configuration for cryptodefender project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path , include
from core import views
from deep_research import views as dr_views
from protection import views as pr_views
from prevent_guide import views as pg_views
from payment import views as pay_views

from accounts import views as acc_views

from deep_network_scan import views as dns_views 

from logs_monitering import views as lm_views




urlpatterns = [
    path('admin/', admin.site.urls),

    # App routes
    path('', views.home, name='home'),
    path('detect/', views.detect, name='detect'),
        # Auth routes
    path('signup/', views.signup_view, name='signup'),
    path('verify-signup-otp/', views.verify_signup_otp, name='verify_signup_otp'),
    path('login/', views.login_view, name='login'),
    path('profile/', views.profile_view, name='profile'),


        #API
    path('api/scan-result/', views.receive_scan, name='receive_scan'),

    path('api/scan/', dr_views.scan_result, name='scan_result'),

    path('home_loggedin/', views.home_loggedin, name='home_loggedin'),
    path('logout/', views.logout_view, name='logout'),

      # 🔍 New Apps Routes

    path('deep-research/', dr_views.deep_research, name='deep_research'),

    
    path('protection/', pr_views.protection, name='protection'),

    path('payment/', pay_views.payment, name='payment'),


    # 🔥 ADMIN PANEL (CUSTOM)
    path('admin-login/', acc_views.admin_login, name='admin_login'), 
    path('admin-dashboard/', acc_views.admin_dashboard, name='admin_dashboard'), 
    path('manage-admins/', acc_views.manage_admins, name='manage_admins'), 
    path('admin-logout/', acc_views.admin_logout, name='admin_logout'),


    # 🌐 Deep Network Scan
    path('deep-network-scan/', dns_views.network_scan_view, name='deep_network_scan'),
    path('deep-network-scan/api/scan/', dns_views.api_scan, name='deep_network_scan_api'),

    path('prevent-guide/', pg_views.prevent_guide, name='prevent_guide'),
    path('api/cleanup-mining/', pg_views.cleanup_mining, name='cleanup_mining'),




    path('logs-monitoring/', lm_views.logs_monitoring, name='logs_monitoring'),



]


