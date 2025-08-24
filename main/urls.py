from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('home/', views.home, name='home'),
    path('login/', views.login_view, name='login'),   # use login_view in views.py
    path('logout/', views.logout_view, name='logout'), # add logout URL
    path('reg/', views.reg, name='reg'),
    path('setting/', views.index, name='setting'),  # fix to views.setting
]
