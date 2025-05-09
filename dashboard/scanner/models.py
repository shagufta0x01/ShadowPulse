from django.db import models
from django.utils import timezone
import json

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


class NetworkMonitorLog(models.Model):
    """Model for logging network monitoring events"""
    EVENT_TYPES = [
        ('monitor_start', 'Monitor Started'),
        ('monitor_stop', 'Monitor Stopped'),
        ('error', 'Error'),
        ('info', 'Information'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    description = models.TextField()

    def __str__(self):
        return f"{self.get_event_type_display()} at {self.timestamp}"


class NetworkTrafficStats(models.Model):
    """Model for storing network traffic statistics"""
    timestamp = models.DateTimeField(auto_now_add=True)
    packets_captured = models.IntegerField(default=0)
    bytes_captured = models.BigIntegerField(default=0)
    packets_per_second = models.FloatField(default=0.0)
    bytes_per_second = models.FloatField(default=0.0)
    protocol_distribution = models.TextField(default='{}')  # JSON string
    active_connections = models.IntegerField(default=0)
    unique_ips = models.IntegerField(default=0)

    def __str__(self):
        return f"Traffic Stats at {self.timestamp}"

    def get_protocol_distribution(self):
        """Return the protocol distribution as a dictionary"""
        try:
            return json.loads(self.protocol_distribution)
        except json.JSONDecodeError:
            return {}


class NetworkAlert(models.Model):
    """Model for storing network security alerts"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    alert_type = models.CharField(max_length=50)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    packet_info = models.TextField(null=True, blank=True)  # JSON string
    resolved = models.BooleanField(default=False)
    resolution_notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.alert_type} ({self.severity}) at {self.timestamp}"

    def get_packet_info(self):
        """Return the packet info as a dictionary"""
        if not self.packet_info:
            return None
        try:
            return json.loads(self.packet_info)
        except json.JSONDecodeError:
            return None


class VulnerabilityCheckup(models.Model):
    """Model for storing vulnerability checkup results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='vulnerability_checkups')
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    scan_type = models.CharField(max_length=50, default='standard')
    total_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)
    scan_duration = models.DurationField(null=True, blank=True)

    def __str__(self):
        return f"Vulnerability Checkup for {self.target} at {self.timestamp}"


class Vulnerability(models.Model):
    """Model for storing individual vulnerabilities"""
    SEVERITY_CHOICES = [
        ('unknown', 'Unknown'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    # Optional link to vulnerability checkup
    checkup = models.ForeignKey(VulnerabilityCheckup, on_delete=models.CASCADE, related_name='vulnerabilities', null=True, blank=True)
    # Optional link to port info (for port-based vulnerabilities)
    port_info = models.ForeignKey('PortInfo', on_delete=models.CASCADE, related_name='vulnerabilities', null=True, blank=True)
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cve_id = models.CharField(max_length=20, blank=True, null=True)  # CVE identifier if available
    affected_component = models.CharField(max_length=255)
    remediation_steps = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    cvss_score = models.FloatField(default=0.0, blank=True, null=True)  # CVSS score if available

    def __str__(self):
        return f"{self.title} ({self.severity}) on {self.target}"


class PortScanResult(models.Model):
    """Model for storing port scan results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='port_scans')
    scan_type = models.CharField(max_length=50, default='standard')
    port_range = models.CharField(max_length=255, default='1-1024')
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    open_ports_count = models.IntegerField(default=0)
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Port scan of {self.target} at {self.start_time}"

    class Meta:
        ordering = ['-start_time']


class PortInfo(models.Model):
    """Model for storing information about individual ports"""
    scan_result = models.ForeignKey(PortScanResult, on_delete=models.CASCADE, related_name='port_info')
    port_number = models.IntegerField()
    is_open = models.BooleanField(default=True)
    service_name = models.CharField(max_length=100, default='unknown')
    service_version = models.CharField(max_length=100, blank=True, null=True)
    banner = models.TextField(blank=True, null=True)
    protocol = models.CharField(max_length=10, default='tcp')
    notes = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Port {self.port_number} ({self.service_name}) on scan {self.scan_result.id}"

    class Meta:
        ordering = ['port_number']


class InstalledSoftware(models.Model):
    """Model for storing information about installed software"""
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='installed_software')
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100, blank=True, null=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    install_date = models.DateField(blank=True, null=True)
    install_location = models.CharField(max_length=255, blank=True, null=True)
    is_vulnerable = models.BooleanField(default=False)
    last_checked = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        version_str = f" {self.version}" if self.version else ""
        return f"{self.name}{version_str} on {self.target}"

    class Meta:
        unique_together = ('target', 'name', 'version')
        ordering = ['name']


class SoftwareVulnerabilityScan(models.Model):
    """Model for storing software vulnerability scan results"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='software_vulnerability_scans')
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    total_software = models.IntegerField(default=0)
    vulnerable_software = models.IntegerField(default=0)
    total_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)

    def __str__(self):
        return f"Software vulnerability scan for {self.target} at {self.start_time}"

    class Meta:
        ordering = ['-start_time']


class SoftwareVulnerability(models.Model):
    """Model for storing individual software vulnerabilities"""
    SEVERITY_CHOICES = [
        ('unknown', 'Unknown'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    scan = models.ForeignKey(SoftwareVulnerabilityScan, on_delete=models.CASCADE, related_name='vulnerabilities')
    software = models.ForeignKey(InstalledSoftware, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    cve_id = models.CharField(max_length=20, blank=True, null=True)
    cvss_score = models.FloatField(default=0.0, blank=True, null=True)
    affected_versions = models.CharField(max_length=255, blank=True, null=True)
    remediation_steps = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    discovered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cve_id or self.title} ({self.severity}) for {self.software.name}"

    class Meta:
        ordering = ['-cvss_score', 'severity']
