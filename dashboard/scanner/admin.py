from django.contrib import admin
from .models import Target, ScanResult, NetworkDevice

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'hostname', 'is_active', 'last_scan', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('ip_address', 'hostname', 'description')

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('target', 'scan_type', 'scan_time')
    list_filter = ('scan_type', 'scan_time')
    search_fields = ('target__ip_address', 'scan_type')

@admin.register(NetworkDevice)
class NetworkDeviceAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'mac_address', 'vendor', 'last_seen')
    list_filter = ('vendor', 'last_seen')
    search_fields = ('ip_address', 'mac_address', 'vendor', 'hostname')
