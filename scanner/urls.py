from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/', views.start_scan, name='start_scan'),
    path('scan/<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scan/<int:scan_id>/download/', views.download_report, name='download_report'),
    path('scan/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),
    path('history/', views.scan_history, name='history'),
    path('history/clear/', views.clear_history, name='clear_history'),
    path('api/history/', views.api_history, name='api_history'),
]