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
from django.urls import path
from core import views
from deep_research import views as dr_views
from protection import views as pr_views
from prevent_guide import views as pg_views
from payment import views as pay_views
urlpatterns = [
    path('admin/', admin.site.urls),

    # App routes
    path('', views.home, name='home'),
    path('detect/', views.detect, name='detect'),
        # Auth routes
    path('signup/', views.signup_view, name='signup'),
    path('verify-signup-otp/', views.verify_signup_otp, name='verify_signup_otp'),
    path('login/', views.login_view, name='login'),
    
    path('api/scan-result/', views.receive_scan, name='receive_scan'),



    path('home_loggedin/', views.home_loggedin, name='home_loggedin'),
    path('logout/', views.logout_view, name='logout'),

      # 🔍 New Apps Routes

    path('deep-research/', dr_views.deep_research, name='deep_research'),
    path('protection/', pr_views.protection, name='protection'),
    path('prevent-guide/', pg_views.prevent_guide, name='prevent_guide'),
    path('payment/', pay_views.payment, name='payment'),
]
