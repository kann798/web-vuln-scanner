from django.contrib import admin
from .models import ScanResult


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['url', 'risk_level', 'risk_score', 'vulnerabilities_found', 'scan_duration', 'scan_date']
    list_filter  = ['risk_level', 'status']
    search_fields = ['url']
    readonly_fields = ['scan_date', 'vulnerabilities_json']
    ordering = ['-scan_date']
