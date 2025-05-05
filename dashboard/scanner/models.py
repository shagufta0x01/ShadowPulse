from django.db import models
from django.utils import timezone

class Target(models.Model):
    """Model representing a target system to scan"""
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    last_scan = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or 'Unknown'})"

class ScanResult(models.Model):
    """Model representing a scan result"""
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='scan_results')
    scan_type = models.CharField(max_length=50)
    result_data = models.TextField()
    scan_time = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.scan_type} scan of {self.target} at {self.scan_time}"

class NetworkDevice(models.Model):
    """Model representing a device discovered on the network"""
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('ip_address', 'mac_address')

    def __str__(self):
        return f"{self.ip_address} ({self.vendor or 'Unknown'})"
