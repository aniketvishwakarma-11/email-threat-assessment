from django.urls import path
from . import views

urlpatterns = [
    path('', views.Home, name='home'),
    path('history/', views.history, name='history'),
    path('history/export.csv', views.export_history, name='export_history'),
]