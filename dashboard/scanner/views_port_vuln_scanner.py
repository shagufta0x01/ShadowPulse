"""
Port Vulnerability Scanner Views

This module provides views for the port vulnerability scanner functionality.
"""

import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.utils import timezone
from django.db.models import Count

from .models import Target, PortScanResult, PortInfo, Vulnerability
from .port_vulnerability_scanner import create_port_vuln_scanner, get_port_vuln_scanner, remove_port_vuln_scanner

# Configure logging
logger = logging.getLogger(__name__)

@login_required
def start_port_vuln_scan(request, scan_id):
    """
    Start a vulnerability scan based on port scan results.
    """
    if request.method == 'POST':
        # Get the port scan result
        scan_result = get_object_or_404(PortScanResult, id=scan_id)

        # Check if there are open ports to scan
        if scan_result.port_info.filter(is_open=True).count() == 0:
            return JsonResponse({
                'status': 'error',
                'message': 'No open ports found to scan for vulnerabilities.'
            })

        # Create a new vulnerability scanner
        scanner = create_port_vuln_scanner(scan_result)

        # Start the scan
        if scanner.start_scan():
            # Get process ID for state manager
            process_id = f"port_vuln_scan_{scan_result.id}"

            return JsonResponse({
                'status': 'success',
                'message': 'Vulnerability scan started.',
                'process_id': process_id
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to start vulnerability scan. A scan may already be in progress.'
            })

    # If not POST, redirect to results page
    return redirect('scanner:port_scanner_results', scan_id=scan_id)

@login_required
def port_vuln_scan_status(request):
    """
    Get the status of a port vulnerability scan.
    """
    process_id = request.GET.get('process_id')

    if not process_id:
        return JsonResponse({
            'status': 'error',
            'message': 'Process ID is required.'
        })

    # Check if the process ID is valid
    if not process_id.startswith('port_vuln_scan_'):
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid process ID.'
        })

    # Extract scan ID from process ID
    scan_id = process_id.replace('port_vuln_scan_', '')

    # Get the scanner
    scanner = get_port_vuln_scanner(scan_id)

    if scanner:
        # Get status from scanner
        status = scanner.get_status()
        return JsonResponse(status)

    # If scanner not found, check state manager
    from .state_manager import get_process_data

    data = get_process_data(process_id)

    if data:
        # Get thread status
        from .state_manager import is_thread_alive
        thread_alive = is_thread_alive(process_id)

        # Get minimal data based on request parameters
        minimal = request.GET.get('minimal', 'false').lower() == 'true'

        if not thread_alive and data.get('progress', 0) >= 100:
            # Process is complete, but we'll let the delayed_unregister handle cleanup
            pass

        # Return status from state manager
        response_data = {
            'running': thread_alive,
            'progress': data.get('progress', 0),
            'completed': data.get('completed', False),
            'failed': data.get('failed', False),
        }

        # Add additional data if not minimal request
        if not minimal:
            response_data.update({
                'status_message': data.get('status_message', 'Processing...'),
                'vulnerabilities_found': data.get('vulnerabilities_found', 0),
                'error': data.get('error', '')
            })

        return JsonResponse(response_data)

    # If not found in state manager, return default status
    return JsonResponse({
        'running': False,
        'progress': 0,
        'status_message': 'No active scan',
        'vulnerabilities_found': 0
    })

@login_required
def stop_port_vuln_scan(request, scan_id):
    """
    Stop a running port vulnerability scan.
    """
    # Get the scanner
    scanner = get_port_vuln_scanner(scan_id)

    if scanner:
        # Stop the scan
        if scanner.stop_scan():
            return JsonResponse({
                'status': 'success',
                'message': 'Vulnerability scan stopped.'
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to stop vulnerability scan.'
            })

    # If scanner not found, check state manager
    from .state_manager import get_all_processes, unregister_process

    process_id = f"port_vuln_scan_{scan_id}"

    # Unregister the process
    unregister_process(process_id)

    return JsonResponse({
        'status': 'success',
        'message': 'Vulnerability scan stopped.'
    })

@login_required
def port_vuln_scan_results(request, scan_id):
    """
    View results of a port vulnerability scan.
    """
    # Get the port scan result
    scan_result = get_object_or_404(PortScanResult, id=scan_id)

    # Get vulnerabilities for this scan
    vulnerabilities = Vulnerability.objects.filter(port_info__scan_result=scan_result)

    # Group vulnerabilities by severity
    severity_counts = {
        'critical': vulnerabilities.filter(severity='critical').count(),
        'high': vulnerabilities.filter(severity='high').count(),
        'medium': vulnerabilities.filter(severity='medium').count(),
        'low': vulnerabilities.filter(severity='low').count(),
        'unknown': vulnerabilities.filter(severity='unknown').count()
    }

    context = {
        'scan_result': scan_result,
        'vulnerabilities': vulnerabilities,
        'severity_counts': severity_counts,
        'page_title': f'Vulnerability Scan Results - {scan_result.target.ip_address}',
        'active_tab': 'port_scanner'
    }

    return render(request, 'scanner/port_vuln_scan_results.html', context)
