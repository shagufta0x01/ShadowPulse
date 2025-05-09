"""
Views for network monitoring and vulnerability scanning functionality.
"""

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Count, Q
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator

from .models import (
    Target, NetworkMonitorLog, NetworkTrafficStats, NetworkAlert,
    VulnerabilityCheckup, Vulnerability
)
from .network_monitor import get_monitor
from .vulnerability_scanner import get_scanner, create_scanner, remove_scanner


@login_required
def network_monitor_dashboard(request):
    """Network monitoring dashboard view."""
    # Get monitor instance
    monitor = get_monitor()
    
    # Get latest traffic stats
    latest_stats = NetworkTrafficStats.objects.order_by('-timestamp').first()
    
    # Get recent alerts
    recent_alerts = NetworkAlert.objects.order_by('-timestamp')[:10]
    
    # Get alert counts by severity
    alert_counts = {
        'critical': NetworkAlert.objects.filter(severity='critical').count(),
        'high': NetworkAlert.objects.filter(severity='high').count(),
        'medium': NetworkAlert.objects.filter(severity='medium').count(),
        'low': NetworkAlert.objects.filter(severity='low').count(),
    }
    
    # Get monitor status
    monitor_status = {
        'running': monitor.running if monitor else False,
        'start_time': monitor.stats.get('start_time') if monitor and monitor.running else None,
        'packets_captured': monitor.stats.get('packets_captured', 0) if monitor else 0,
    }
    
    context = {
        'page_title': 'Network Monitoring',
        'monitor_status': monitor_status,
        'latest_stats': latest_stats,
        'recent_alerts': recent_alerts,
        'alert_counts': alert_counts,
    }
    
    return render(request, 'scanner/network_monitor.html', context)


@login_required
def start_network_monitor(request):
    """Start the network monitoring process."""
    if request.method == 'POST':
        monitor = get_monitor()
        
        if monitor:
            # Get interface from request if provided
            interface = request.POST.get('interface')
            if interface:
                monitor.interface = interface
            
            # Start monitoring
            success = monitor.start_monitoring()
            
            if success:
                messages.success(request, 'Network monitoring started successfully.')
            else:
                messages.error(request, 'Failed to start network monitoring. It may already be running.')
        else:
            messages.error(request, 'Failed to initialize network monitor.')
    
    return redirect('scanner:network_monitor_dashboard')


@login_required
def stop_network_monitor(request):
    """Stop the network monitoring process."""
    if request.method == 'POST':
        monitor = get_monitor()
        
        if monitor:
            # Stop monitoring
            success = monitor.stop_monitoring()
            
            if success:
                messages.success(request, 'Network monitoring stopped successfully.')
            else:
                messages.error(request, 'Failed to stop network monitoring. It may not be running.')
        else:
            messages.error(request, 'Failed to access network monitor.')
    
    return redirect('scanner:network_monitor_dashboard')


@login_required
def network_monitor_stats(request):
    """Get current network monitoring statistics."""
    monitor = get_monitor()
    
    if monitor:
        stats = monitor.get_statistics()
        return JsonResponse(stats)
    else:
        return JsonResponse({'error': 'Network monitor not initialized'}, status=500)


@login_required
def network_alerts(request):
    """View for listing network alerts."""
    # Get filter parameters
    severity = request.GET.get('severity')
    resolved = request.GET.get('resolved')
    alert_type = request.GET.get('type')
    
    # Base queryset
    alerts = NetworkAlert.objects.order_by('-timestamp')
    
    # Apply filters
    if severity:
        alerts = alerts.filter(severity=severity)
    
    if resolved is not None:
        is_resolved = resolved.lower() == 'true'
        alerts = alerts.filter(resolved=is_resolved)
    
    if alert_type:
        alerts = alerts.filter(alert_type=alert_type)
    
    # Paginate results
    paginator = Paginator(alerts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get alert types for filter
    alert_types = NetworkAlert.objects.values('alert_type').annotate(count=Count('id')).order_by('alert_type')
    
    context = {
        'page_title': 'Network Security Alerts',
        'page_obj': page_obj,
        'alert_types': alert_types,
        'current_filters': {
            'severity': severity,
            'resolved': resolved,
            'type': alert_type,
        }
    }
    
    return render(request, 'scanner/network_alerts.html', context)


@login_required
def resolve_alert(request, alert_id):
    """Mark an alert as resolved."""
    if request.method == 'POST':
        alert = get_object_or_404(NetworkAlert, id=alert_id)
        
        # Get resolution notes
        resolution_notes = request.POST.get('resolution_notes', '')
        
        # Update alert
        alert.resolved = True
        alert.resolution_notes = resolution_notes
        alert.save()
        
        messages.success(request, 'Alert marked as resolved.')
    
    return redirect('scanner:network_alerts')


@login_required
def vulnerability_dashboard(request):
    """Vulnerability management dashboard view."""
    # Get recent vulnerability checkups
    recent_checkups = VulnerabilityCheckup.objects.order_by('-timestamp')[:5]
    
    # Get vulnerability counts by severity
    vuln_counts = {
        'critical': Vulnerability.objects.filter(severity='critical').count(),
        'high': Vulnerability.objects.filter(severity='high').count(),
        'medium': Vulnerability.objects.filter(severity='medium').count(),
        'low': Vulnerability.objects.filter(severity='low').count(),
    }
    
    # Get vulnerability counts by status
    status_counts = {
        'open': Vulnerability.objects.filter(status='open').count(),
        'in_progress': Vulnerability.objects.filter(status='in_progress').count(),
        'resolved': Vulnerability.objects.filter(status='resolved').count(),
        'false_positive': Vulnerability.objects.filter(status='false_positive').count(),
    }
    
    # Get targets
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')
    
    context = {
        'page_title': 'Vulnerability Management',
        'recent_checkups': recent_checkups,
        'vuln_counts': vuln_counts,
        'status_counts': status_counts,
        'targets': targets,
    }
    
    return render(request, 'scanner/vulnerability_dashboard.html', context)


@login_required
def start_vulnerability_scan(request):
    """Start a vulnerability scan for a target."""
    if request.method == 'POST':
        target_id = request.POST.get('target_id')
        scan_type = request.POST.get('scan_type', 'standard')
        
        if not target_id:
            messages.error(request, 'No target selected.')
            return redirect('scanner:vulnerability_dashboard')
        
        # Get target
        target = get_object_or_404(Target, id=target_id)
        
        # Create scanner
        scanner = create_scanner(target, scan_type)
        
        # Start scan
        success = scanner.start_scan()
        
        if success:
            messages.success(request, f'Vulnerability scan started for {target}.')
        else:
            messages.error(request, f'Failed to start vulnerability scan for {target}.')
    
    return redirect('scanner:vulnerability_dashboard')


@login_required
def stop_vulnerability_scan(request):
    """Stop a vulnerability scan for a target."""
    if request.method == 'POST':
        target_id = request.POST.get('target_id')
        
        if not target_id:
            messages.error(request, 'No target specified.')
            return redirect('scanner:vulnerability_dashboard')
        
        # Get scanner
        scanner = get_scanner(target_id)
        
        if scanner:
            # Stop scan
            success = scanner.stop_scan()
            
            if success:
                messages.success(request, 'Vulnerability scan stopped.')
            else:
                messages.error(request, 'Failed to stop vulnerability scan.')
            
            # Remove scanner
            remove_scanner(target_id)
        else:
            messages.error(request, 'No active scan found for this target.')
    
    return redirect('scanner:vulnerability_dashboard')


@login_required
def vulnerability_scan_status(request, target_id):
    """Get the status of a vulnerability scan."""
    scanner = get_scanner(target_id)
    
    if scanner:
        status = scanner.get_status()
        return JsonResponse(status)
    else:
        return JsonResponse({'running': False, 'progress': 0, 'status_message': 'No active scan'})


@login_required
def vulnerability_checkup_detail(request, checkup_id):
    """View details of a vulnerability checkup."""
    checkup = get_object_or_404(VulnerabilityCheckup, id=checkup_id)
    
    # Get vulnerabilities for this checkup
    vulnerabilities = Vulnerability.objects.filter(checkup=checkup).order_by('-severity', 'title')
    
    context = {
        'page_title': f'Vulnerability Checkup: {checkup.target}',
        'checkup': checkup,
        'vulnerabilities': vulnerabilities,
    }
    
    return render(request, 'scanner/vulnerability_checkup_detail.html', context)


@login_required
def vulnerabilities_list(request):
    """View for listing vulnerabilities."""
    # Get filter parameters
    severity = request.GET.get('severity')
    status = request.GET.get('status')
    target_id = request.GET.get('target')
    
    # Base queryset
    vulnerabilities = Vulnerability.objects.order_by('-severity', '-discovered_at')
    
    # Apply filters
    if severity:
        vulnerabilities = vulnerabilities.filter(severity=severity)
    
    if status:
        vulnerabilities = vulnerabilities.filter(status=status)
    
    if target_id:
        vulnerabilities = vulnerabilities.filter(target_id=target_id)
    
    # Paginate results
    paginator = Paginator(vulnerabilities, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get targets for filter
    targets = Target.objects.filter(is_active=True).order_by('ip_address')
    
    context = {
        'page_title': 'Vulnerabilities',
        'page_obj': page_obj,
        'targets': targets,
        'current_filters': {
            'severity': severity,
            'status': status,
            'target': target_id,
        }
    }
    
    return render(request, 'scanner/vulnerabilities_list.html', context)


@login_required
def update_vulnerability_status(request, vuln_id):
    """Update the status of a vulnerability."""
    if request.method == 'POST':
        vulnerability = get_object_or_404(Vulnerability, id=vuln_id)
        
        # Get new status and notes
        new_status = request.POST.get('status')
        notes = request.POST.get('notes', '')
        
        if new_status in dict(Vulnerability.STATUS_CHOICES).keys():
            # Update vulnerability
            vulnerability.status = new_status
            vulnerability.save()
            
            messages.success(request, f'Vulnerability status updated to {new_status}.')
        else:
            messages.error(request, 'Invalid status value.')
    
    # Redirect back to referring page or vulnerabilities list
    referer = request.META.get('HTTP_REFERER')
    if referer:
        return redirect(referer)
    else:
        return redirect('scanner:vulnerabilities_list')
