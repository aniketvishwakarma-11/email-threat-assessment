from django.contrib import admin

from .models import ScanRecord


@admin.register(ScanRecord)
class ScanRecordAdmin(admin.ModelAdmin):
    list_display = ("created_at", "scan_type", "verdict", "confidence")
    list_filter = ("scan_type", "verdict", "created_at")
    readonly_fields = ("created_at",)
