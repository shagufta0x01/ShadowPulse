"""
Views for the port scanner functionality.
"""

import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.utils import timezone
from django.db.models import Count, Q
from django.core.paginator import Paginator
from .models import Target, PortScanResult, PortInfo
from .port_scanner import create_port_scanner, get_port_scanner, remove_port_scanner

# Configure logging
logger = logging.getLogger(__name__)

@login_required
def port_scanner_home(request):
    """
    Main port scanner page.
    """
    # Get all targets
    targets = Target.objects.filter(is_active=True).order_by('ip_address')

    # Get recent scans
    recent_scans = PortScanResult.objects.all().order_by('-start_time')[:10]

    # Get statistics
    total_scans = PortScanResult.objects.count()
    completed_scans = PortScanResult.objects.filter(status='completed').count()
    failed_scans = PortScanResult.objects.filter(status='failed').count()

    # Get port statistics
    common_ports = PortInfo.objects.filter(is_open=True).values('port_number', 'service_name') \
                  .annotate(count=Count('id')).order_by('-count')[:10]

    context = {
        'targets': targets,
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'common_ports': common_ports,
        'page_title': 'Port Scanner',
        'active_tab': 'port_scanner'
    }

    return render(request, 'scanner/port_scanner.html', context)

@login_required
def start_port_scan(request):
    """
    Start a new port scan.
    """
    if request.method == 'POST':
        target_id = request.POST.get('target_id')
        scan_type = request.POST.get('scan_type', 'standard')
        port_range = request.POST.get('port_range')
        custom_nmap_args = request.POST.get('custom_nmap_args')

        # Validate inputs
        if not target_id:
            return JsonResponse({'status': 'error', 'message': 'Target ID is required'})

        # Get target
        try:
            target = Target.objects.get(id=target_id)
        except Target.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Target not found'})

        # Validate custom nmap arguments if provided
        if scan_type == 'custom' and not custom_nmap_args:
            return JsonResponse({'status': 'error', 'message': 'Custom nmap arguments are required for custom scan type'})

        # Create scanner
        scanner = create_port_scanner(target, scan_type, port_range, custom_nmap_args)

        # Start scan
        success = scanner.start_scan()

        if success:
            # Store scan ID in session for state management
            if 'active_scans' not in request.session:
                request.session['active_scans'] = {}

            request.session['active_scans'][str(target.id)] = {
                'scan_id': scanner.scan_result.id,
                'scan_type': 'port_scan',
                'start_time': scanner.start_time.isoformat() if scanner.start_time else None
            }
            request.session.modified = True

            return redirect('scanner:port_scanner_results', scan_id=scanner.scan_result.id)
        else:
            return JsonResponse({'status': 'error', 'message': 'Failed to start scan'})

    # If not POST, redirect to home
    return redirect('scanner:port_scanner_home')

@login_required
def stop_port_scan(request, target_id):
    """
    Stop a running port scan.
    """
    # Get scanner
    scanner = get_port_scanner(target_id)

    if scanner and scanner.running:
        # Stop scan
        success = scanner.stop_scan()

        if success:
            return JsonResponse({'status': 'success', 'message': 'Scan stopped'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Failed to stop scan'})

    return JsonResponse({'status': 'error', 'message': 'No active scan found for this target'})

@login_required
def scan_status(request, target_id):
    """
    Get the status of a running port scan.
    """
    # First check the state manager
    from .state_manager import get_all_processes

    all_processes = get_all_processes()
    for process_id, process_info in all_processes.items():
        if (process_info.get('type') == 'port_scan' and
            process_info.get('data', {}).get('target_id') == str(target_id)):

            # Found a matching process in the state manager
            data = process_info.get('data', {})

            # Check if the process is still running
            thread_alive = process_info.get('thread_alive', False)

            # If the process is complete, check if we should remove it
            if not thread_alive and data.get('progress', 0) >= 100:
                # Process is complete, but we'll let the delayed_unregister handle cleanup
                pass

            # Return status from state manager
            return JsonResponse({
                'running': thread_alive,
                'progress': data.get('progress', 0),
                'status_message': data.get('status_message', 'Processing...'),
                'open_ports_count': data.get('open_ports_count', 0),
                'scan_result_id': data.get('scan_id'),
                'scan_method': data.get('scan_method', 'unknown'),
                'debug_info': {
                    'process_id': process_id,
                    'thread_alive': thread_alive,
                    'data_keys': list(data.keys())
                }
            })

    # If not found in state manager, check active scanners
    scanner = get_port_scanner(target_id)

    if scanner:
        # Get status
        status = scanner.get_status()

        # If scan is complete, remove scanner
        if not scanner.running and status['progress'] >= 100:
            remove_port_scanner(target_id)

        return JsonResponse(status)

    # Check if there's an entry in the session
    active_scans = request.session.get('active_scans', {})
    if str(target_id) in active_scans:
        scan_info = active_scans[str(target_id)]
        if scan_info.get('scan_type') == 'port_scan':
            # Get the scan result
            try:
                scan_result = PortScanResult.objects.get(id=scan_info.get('scan_id'))
                return JsonResponse({
                    'running': scan_result.status == 'in_progress',
                    'progress': 100 if scan_result.status == 'completed' else 0,
                    'status_message': f"Scan {scan_result.status}",
                    'open_ports_count': scan_result.open_ports_count,
                    'scan_result_id': scan_result.id
                })
            except PortScanResult.DoesNotExist:
                # Remove from session
                del active_scans[str(target_id)]
                request.session.modified = True

    # No active scan found
    return JsonResponse({
        'running': False,
        'progress': 0,
        'status_message': 'No active scan',
        'open_ports_count': 0
    })

@login_required
def port_scanner_results(request, scan_id):
    """
    View results of a port scan.
    """
    # Get scan result
    scan_result = get_object_or_404(PortScanResult, id=scan_id)

    # Get port info
    port_info = scan_result.port_info.all().order_by('port_number')

    # Group ports by service
    services = {}
    for port in port_info:
        service = port.service_name
        if service not in services:
            services[service] = []
        services[service].append(port)

    # Sort services by count
    sorted_services = sorted(services.items(), key=lambda x: len(x[1]), reverse=True)

    context = {
        'scan_result': scan_result,
        'port_info': port_info,
        'services': sorted_services,
        'page_title': f'Port Scan Results - {scan_result.target.ip_address}',
        'active_tab': 'port_scanner'
    }

    return render(request, 'scanner/port_scanner_results.html', context)

@login_required
def port_scanner_results_ajax(request, scan_id):
    """
    View results of a port scan via AJAX.
    Returns only the results portion of the page.
    """
    # Get scan result
    scan_result = get_object_or_404(PortScanResult, id=scan_id)

    # Get port info
    port_info = scan_result.port_info.all().order_by('port_number')

    # Group ports by service
    services = {}
    for port in port_info:
        service = port.service_name
        if service not in services:
            services[service] = []
        services[service].append(port)

    # Sort services by count
    sorted_services = sorted(services.items(), key=lambda x: len(x[1]), reverse=True)

    from django.utils import timezone

    context = {
        'scan_result': scan_result,
        'port_info': port_info,
        'services': sorted_services,
        'is_ajax': True,
        'now': timezone.now()
    }

    return render(request, 'scanner/port_scanner_results_partial.html', context)

@login_required
def port_scanner_history(request):
    """
    View history of port scans.
    """
    # Get all scan results
    scan_results = PortScanResult.objects.all().order_by('-start_time')

    # Filter by target if specified
    target_id = request.GET.get('target_id')
    if target_id:
        scan_results = scan_results.filter(target_id=target_id)

    # Filter by status if specified
    status = request.GET.get('status')
    if status:
        scan_results = scan_results.filter(status=status)

    # Paginate results
    paginator = Paginator(scan_results, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Get all targets for filter dropdown
    targets = Target.objects.filter(is_active=True).order_by('ip_address')

    context = {
        'page_obj': page_obj,
        'targets': targets,
        'selected_target': target_id,
        'selected_status': status,
        'page_title': 'Port Scanner History',
        'active_tab': 'port_scanner'
    }

    return render(request, 'scanner/port_scanner_history.html', context)

@login_required
def port_details(request, port_id):
    """
    View detailed information about a specific port.
    """
    # Get port info
    port_info = get_object_or_404(PortInfo, id=port_id)

    # Get scan result
    scan_result = port_info.scan_result

    context = {
        'port_info': port_info,
        'scan_result': scan_result,
        'page_title': f'Port {port_info.port_number} Details',
        'active_tab': 'port_scanner'
    }

    return render(request, 'scanner/port_details.html', context)

@login_required
def export_scan_results(request, scan_id):
    """
    Export port scan results in various formats.
    """
    # Get scan result
    scan_result = get_object_or_404(PortScanResult, id=scan_id)

    # Get port info
    port_info = scan_result.port_info.all().order_by('port_number')

    # Get export format
    export_format = request.GET.get('format', 'json')

    if export_format == 'json':
        # Create JSON data
        data = {
            'scan_id': scan_result.id,
            'target': scan_result.target.ip_address,
            'scan_type': scan_result.scan_type,
            'port_range': scan_result.port_range,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'duration': str(scan_result.duration) if scan_result.duration else None,
            'status': scan_result.status,
            'open_ports_count': scan_result.open_ports_count,
            'ports': []
        }

        for port in port_info:
            data['ports'].append({
                'port_number': port.port_number,
                'is_open': port.is_open,
                'service_name': port.service_name,
                'service_version': port.service_version,
                'banner': port.banner,
                'protocol': port.protocol
            })

        # Create response
        response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="port_scan_{scan_id}.json"'

    elif export_format == 'csv':
        # Create CSV data
        import csv
        from io import StringIO

        csv_data = StringIO()
        writer = csv.writer(csv_data)

        # Write header
        writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Version', 'Banner'])

        # Write data
        for port in port_info:
            writer.writerow([
                port.port_number,
                port.protocol,
                'open' if port.is_open else 'closed',
                port.service_name,
                port.service_version or '',
                port.banner or ''
            ])

        # Create response
        response = HttpResponse(csv_data.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="port_scan_{scan_id}.csv"'

    elif export_format == 'nmap':
        # Create nmap-like output
        nmap_output = f"""
# Nmap-like scan report for {scan_result.target.ip_address}
# Scan started at {scan_result.start_time}
# Scan type: {scan_result.scan_type}
# Port range: {scan_result.port_range}

PORT     STATE  SERVICE     VERSION
"""

        for port in port_info:
            state = 'open' if port.is_open else 'closed'
            version = f"{port.service_version}" if port.service_version else ''
            nmap_output += f"{port.port_number:<8} {state:<6} {port.service_name:<12} {version}\n"

        if scan_result.end_time:
            nmap_output += f"\n# Scan completed at {scan_result.end_time}"
            if scan_result.duration:
                nmap_output += f"\n# Scan duration: {scan_result.duration}"

        nmap_output += f"\n# {scan_result.open_ports_count} open ports found"

        # Create response
        response = HttpResponse(nmap_output, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="port_scan_{scan_id}.txt"'

    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid export format'})

    return response

@login_required
def delete_scan_result(request, scan_id):
    """
    Delete a port scan result.
    """
    if request.method == 'POST':
        # Get scan result
        scan_result = get_object_or_404(PortScanResult, id=scan_id)

        # Delete scan result
        scan_result.delete()

        return redirect('scanner:port_scanner_history')

    # If not POST, redirect to history
    return redirect('scanner:port_scanner_history')

@login_required
def update_scan_notes(request):
    """
    Update the notes for a port scan result.
    """
    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        notes = request.POST.get('notes')

        if not scan_id or not notes:
            return JsonResponse({'status': 'error', 'message': 'Scan ID and notes are required'})

        try:
            scan_result = PortScanResult.objects.get(id=scan_id)

            # Append to existing notes if they exist
            if scan_result.notes:
                if 'Method:' not in scan_result.notes:
                    scan_result.notes += f"\n{notes}"
            else:
                scan_result.notes = notes

            scan_result.save()

            return JsonResponse({'status': 'success'})
        except PortScanResult.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Scan result not found'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def vanish_port_scanner_data(request):
    """
    Clear all port scanner data.
    """
    if request.method == 'POST':
        try:
            # Delete all port info
            PortInfo.objects.all().delete()

            # Delete all port scan results
            PortScanResult.objects.all().delete()

            # Return success message
            return JsonResponse({'status': 'success', 'message': 'Port scanner data has been cleared successfully.'})
        except Exception as e:
            logger.error(f"Error clearing port scanner data: {str(e)}")
            return JsonResponse({'status': 'error', 'message': f'Error clearing port scanner data: {str(e)}'})

    # If not POST, redirect to home
    return redirect('scanner:port_scanner_home')

@login_required
def check_nmap_availability(request):
    """
    Check if nmap is available on the system.
    """
    import shutil
    import subprocess

    # Check if nmap binary is available
    nmap_path = shutil.which('nmap')

    # If nmap binary is found, check if it's working
    nmap_working = False
    if nmap_path:
        try:
            # Try to run nmap version command
            result = subprocess.run([nmap_path, '--version'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'Nmap version' in result.stdout:
                nmap_working = True
                logger.info(f"Nmap found and working: {nmap_path}")
        except Exception as e:
            logger.warning(f"Nmap found but not working: {str(e)}")

    # Check if python-nmap is installed
    python_nmap_available = False
    try:
        import nmap
        python_nmap_available = True
        logger.info("python-nmap library found")
    except ImportError:
        logger.warning("python-nmap library not found")

    # Nmap is available if either the binary is working or python-nmap is installed
    nmap_available = nmap_working or python_nmap_available

    return JsonResponse({
        'nmap_available': nmap_available,
        'nmap_path': nmap_path if nmap_working else None,
        'python_nmap_available': python_nmap_available
    })
