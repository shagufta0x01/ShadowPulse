from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import logging
import html

# Get a logger for this file
logger = logging.getLogger('scanner')
import socket
import struct
import sys
import os
import zlib
import time
import json
from .utils import format_command_output
from .memory_protection import MemoryProtectionCheck

# Add the project root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import the protocol and utility modules
from proto.pro.protocol import *

# List of available OS info sections
OS_INFO_SECTIONS = [
    # System Overview
    {"id": "system_overview", "name": "System Overview", "category": "System Information"},
    {"id": "os_details", "name": "Operating System Details", "category": "System Information"},
    {"id": "environment_variables", "name": "Environment Variables", "category": "System Information"},
    {"id": "user_folders", "name": "User Folders", "category": "System Information"},
    {"id": "file_version", "name": "File Version", "category": "System Information"},
    {"id": "running_processes", "name": "Running Processes", "category": "System Information"},

    # Software & Updates
    {"id": "installed_software", "name": "Installed Software", "category": "Software & Updates"},
    {"id": "installed_hotfixes", "name": "Installed Hotfixes", "category": "Software & Updates"},
    {"id": "windows_updates", "name": "Windows Updates", "category": "Software & Updates"},

    # Security Information
    {"id": "amsi_providers", "name": "AMSI Providers", "category": "Security Information"},
    {"id": "antivirus_info", "name": "Antivirus Information", "category": "Security Information"},
    {"id": "defender_settings", "name": "Windows Defender Settings", "category": "Security Information"},
    {"id": "auto_run_executables", "name": "Auto Run Executables", "category": "Security Information"},
    {"id": "certificates", "name": "Certificates", "category": "Security Information"},
    {"id": "firewall_rules", "name": "Firewall Rules", "category": "Security Information"},
    {"id": "audit_policy", "name": "Audit Policy", "category": "Security Information"},
    {"id": "ntlm_settings", "name": "NTLM Settings", "category": "Security Information"},
    {"id": "rdp_connections", "name": "RDP Connections", "category": "Security Information"},
    {"id": "secure_boot_info", "name": "Secure Boot Info", "category": "Security Information"},
    {"id": "sysmon_config", "name": "Sysmon Config", "category": "Security Information"},
    {"id": "uac_policies", "name": "UAC Policies", "category": "Security Information"},

    # User Information
    {"id": "local_groups", "name": "Local Groups", "category": "User Information"},
    {"id": "local_users", "name": "Local Users", "category": "User Information"},
    {"id": "powershell_history", "name": "PowerShell History", "category": "User Information"}
]

# Create a simplified version of the build_request_header function
def build_request_header(version, req_id, cmd_code, payload_len):
    return struct.pack(
        HEADER_FORMAT,
        MAGIC_HEADER,
        version,
        0,  # flags
        req_id,
        cmd_code,
        payload_len,
        0
    )

# Import the arp_scan function from network_utils
from proto.host.network_utils import arp_scan
from .models import Target, ScanResult, NetworkDevice

@login_required
def index(request):
    """Dashboard home page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')
    devices = NetworkDevice.objects.all().order_by('-last_seen')[:10]

    # Get list of target IPs for template
    target_ips = [target.ip_address for target in targets]

    # Show a welcome message only once per session
    if not request.session.get('welcome_shown'):
        messages.info(request, f'Welcome to Rex! Select a target system to begin scanning.')
        request.session['welcome_shown'] = True

    # Get scan results for statistics
    scan_results = ScanResult.objects.all().order_by('-scan_time')

    # Calculate statistics for charts
    scan_types = {}
    scan_dates = {}
    target_scan_counts = {}

    # Process scan results for charts
    for result in scan_results:
        # Count by scan type
        scan_type = result.scan_type
        if scan_type in scan_types:
            scan_types[scan_type] += 1
        else:
            scan_types[scan_type] = 1

        # Count by date (for timeline)
        scan_date = result.scan_time.date().isoformat()
        if scan_date in scan_dates:
            scan_dates[scan_date] += 1
        else:
            scan_dates[scan_date] = 1

        # Count by target
        target_name = f"{result.target.ip_address}"
        if target_name in target_scan_counts:
            target_scan_counts[target_name] += 1
        else:
            target_scan_counts[target_name] = 1

    # Prepare data for charts
    scan_type_labels = list(scan_types.keys())
    scan_type_data = list(scan_types.values())

    # Sort dates for timeline chart
    sorted_dates = sorted(scan_dates.keys())
    timeline_labels = sorted_dates
    timeline_data = [scan_dates[date] for date in sorted_dates]

    # Prepare target scan count data
    target_labels = list(target_scan_counts.keys())
    target_data = list(target_scan_counts.values())

    # Count devices by vendor
    vendor_counts = {}
    for device in devices:
        vendor = device.vendor or "Unknown"
        if vendor in vendor_counts:
            vendor_counts[vendor] += 1
        else:
            vendor_counts[vendor] = 1

    vendor_labels = list(vendor_counts.keys())
    vendor_data = list(vendor_counts.values())

    context = {
        'targets': targets,
        'devices': devices,
        'target_ips': target_ips,
        'page_title': 'Dashboard',
        # Chart data
        'scan_type_labels': scan_type_labels,
        'scan_type_data': scan_type_data,
        'timeline_labels': timeline_labels,
        'timeline_data': timeline_data,
        'target_labels': target_labels,
        'target_data': target_data,
        'vendor_labels': vendor_labels,
        'vendor_data': vendor_data,
        # Summary statistics
        'total_targets': targets.count(),
        'total_devices': devices.count(),
        'total_scans': scan_results.count()
    }
    return render(request, 'scanner/index.html', context)

@login_required
def os_info(request):
    """OS Information page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')

    # Get target ID from query parameters if provided
    target_id = request.GET.get('target_id')
    if target_id:
        selected_target = get_object_or_404(Target, pk=target_id)
    elif targets.exists():
        selected_target = targets.first()
    else:
        selected_target = None

    # System resource data (placeholder values)
    system_resources = {
        'cpu': 40,
        'memory': 70,
        'disk': 50
    }

    # Security status data (placeholder values)
    security_status = {
        'score': 92,
        'critical_issues': 0,
        'warnings': 2,
        'firewall_active': True
    }

    # System overview data
    system_overview = {
        'hostname': selected_target.hostname if selected_target else 'Unknown hostname',
        'ip_address': selected_target.ip_address if selected_target else '192.168.29.244',
        'last_scan': selected_target.last_scan.strftime('%Y-%m-%d %H:%M') if selected_target and selected_target.last_scan else '2023-05-07 14:40',
        'status': 'Secure'  # Placeholder
    }

    # OS details data (placeholder values)
    os_details = {
        'os_name': 'Windows 10 Pro',
        'version': '21H2 (Build 19044.2604)',
        'system_type': '64-bit Operating System, x64-based processor',
        'last_boot': '2023-05-07 09:15:22',
        'critical_vulnerabilities': 0,
        'patch_status': 'Up to date'
    }

    # Group sections by category
    sections_by_category = {}
    for section in OS_INFO_SECTIONS:
        category = section.get('category', 'Uncategorized')
        if category not in sections_by_category:
            sections_by_category[category] = []
        sections_by_category[category].append(section)

    context = {
        'targets': targets,
        'selected_target': selected_target,
        'sections': OS_INFO_SECTIONS,
        'sections_by_category': sections_by_category,
        'page_title': 'OS Information',
        'system_resources': system_resources,
        'security_status': security_status,
        'system_overview': system_overview,
        'os_details': os_details
    }
    return render(request, 'scanner/os_info.html', context)

@login_required
def get_os_info_section(request, target_id, section_id):
    """Get a specific section of OS info from a target"""
    target = get_object_or_404(Target, pk=target_id)

    # Validate section ID
    valid_section_ids = [section["id"] for section in OS_INFO_SECTIONS]
    if section_id not in valid_section_ids:
        messages.error(request, f"Invalid section ID: {section_id}")
        return JsonResponse({
            'status': 'error',
            'message': f"Invalid section ID: {section_id}"
        }, status=400)

    # Define timeout values
    connection_timeout = 15
    receive_timeout = 60
    max_retries = 2

    try:
        # Get section name for display
        section_name = next((section["name"] for section in OS_INFO_SECTIONS if section["id"] == section_id), section_id)

        # Connection with retry logic
        s = None
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                print(f"Connection attempt {attempt + 1} for {target.ip_address}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(connection_timeout)
                s.connect((target.ip_address, 23033))
                break  # Connection successful, exit retry loop
            except (socket.timeout, ConnectionRefusedError) as e:
                last_exception = e
                if s:
                    s.close()
                if attempt < max_retries:
                    print(f"Retrying connection to {target.ip_address} ({attempt + 1}/{max_retries})")
                    time.sleep(2)  # Wait 2 seconds before retrying
                else:
                    # All retries failed
                    raise last_exception

        # Send the command with the section ID as payload
        req_id = 1
        payload = f"{section_id}:{target.ip_address}".encode()
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC_HEADER,
            0x01,  # version
            0,     # flags
            req_id,
            CMD_GET_OS_INFO_SECTION,
            len(payload),
            0      # reserved
        )

        # Send header and payload
        s.sendall(header + payload)

        # Receive the response header
        response_header = s.recv(HEADER_SIZE)
        # Parse header to get flags and payload_len
        _, _, flags, _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, response_header)

        # Check if the response is compressed
        is_compressed = (flags & FLAG_COMPRESSED) != 0
        if is_compressed:
            print(f"Response is compressed. Expecting {payload_len} bytes of compressed data.")

        # Configure socket for better reliability
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # On Windows, we can set TCP keepalive parameters
        if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
            # Set keepalive parameters (enable, idle time in ms, interval in ms)
            s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))

        # Receive the response payload
        s.settimeout(receive_timeout)
        response_payload = b""
        remaining = payload_len

        try:
            print(f"Receiving {payload_len} bytes from {target.ip_address} for section {section_name}")
            chunk_size = 4096  # 4KB chunks

            # Add progress tracking
            total_received = 0
            last_progress = 0

            while remaining > 0:
                chunk = s.recv(min(chunk_size, remaining))
                if not chunk:
                    print(f"Connection closed with {remaining} bytes remaining")
                    break
                response_payload += chunk
                total_received += len(chunk)
                remaining -= len(chunk)

                # Log progress at 25%, 50%, 75% and 100%
                progress = int((total_received / payload_len) * 100)
                if progress >= last_progress + 25:
                    print(f"Progress: {progress}% - Received {total_received} of {payload_len} bytes")
                    last_progress = progress
        except socket.timeout:
            print(f"Socket timeout while receiving data, got {len(response_payload)} of {payload_len} bytes")
            # Continue with partial data if we have some
            if not response_payload:
                raise
        finally:
            s.close()

        # Decompress if needed and decode the response
        if is_compressed:
            try:
                print(f"Decompressing {len(response_payload)} bytes of data")
                decompressed_payload = zlib.decompress(response_payload)
                print(f"Decompressed to {len(decompressed_payload)} bytes")
                result_data = decompressed_payload.decode('utf-8', errors='ignore')
            except zlib.error as e:
                print(f"Error decompressing data: {e}")
                # Try to decode the compressed data as a fallback
                result_data = response_payload.decode('utf-8', errors='ignore')
        else:
            result_data = response_payload.decode('utf-8', errors='ignore')

        # Store the result
        scan_result = ScanResult.objects.create(
            target=target,
            scan_type=f"Section: {section_name}",
            result_data=result_data,
            scan_time=timezone.now()
        )

        # Update the target's last scan time
        target.last_scan = timezone.now()
        target.save()

        # Don't show a success message for every section retrieval
        # This prevents cluttering the UI with too many notifications

        # Special handling for firewall rules section
        if section_id == 'firewall_rules':
            # Check if the result data is already HTML
            if result_data.strip().startswith('<div class="firewall-rules-container">'):
                formatted_data = result_data
            else:
                # Create a simple HTML table for firewall rules
                formatted_data = """
                <div class="firewall-rules-container">
                    <div class="mb-4">
                        <div class="alert alert-info">
                            <i class="fas fa-shield-alt me-2"></i>
                            <strong>Firewall Information</strong>: Showing simplified firewall rules. For detailed rules, run with elevated privileges.
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-12 mb-4">
                            <div class="card">
                                <div class="card-header bg-primary text-white">
                                    <h5 class="mb-0">Windows Firewall Rules</h5>
                                </div>
                                <div class="card-body">
                                    <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">""" + html.escape(result_data) + """</pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                """
        else:
            # Check if the result contains an error message
            if "Error retrieving section" in result_data:
                error_msg = f"Error retrieving section '{section_name}': {result_data}"
                print(f"Error: {error_msg}")
                messages.error(request, error_msg)
                return JsonResponse({
                    'status': 'error',
                    'message': error_msg
                }, status=400)

            # Check if the result is empty
            if not result_data or not result_data.strip():
                error_msg = f"No data returned for section '{section_name}'"
                print(f"Error: {error_msg}")
                messages.error(request, error_msg)
                return JsonResponse({
                    'status': 'error',
                    'message': error_msg
                }, status=400)

            # Format the result data for professional display
            formatted_data = format_command_output(result_data, section_name)

        # Return the result
        return JsonResponse({
            'status': 'success',
            'result_id': scan_result.id,
            'result_data': formatted_data
        })

    except socket.timeout:
        error_msg = f'Connection to {target.ip_address} timed out'
        print(f"Error: {error_msg}")
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

    except ConnectionRefusedError:
        error_msg = f'Connection to {target.ip_address} refused. Make sure the agent is running.'
        print(f"Error: {error_msg}")
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

    except Exception as e:
        import traceback
        error_msg = f'Error: {str(e)}'
        print(f"Unexpected error: {error_msg}")
        print(traceback.format_exc())
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

@login_required
def processes(request):
    """Running Processes page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')

    # Check if we need to refresh the data
    refresh = request.GET.get('refresh', 'false').lower() == 'true'

    # Get the selected target and page
    target_id = request.GET.get('target_id')
    page = request.GET.get('page')
    if target_id:
        target = get_object_or_404(Target, pk=target_id)
    elif targets.exists():
        target = targets.first()
    else:
        target = None

    # Get process data if we have a target
    process_data = None
    if target and refresh:
        try:
            # Send command to get process data
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)  # 30 second timeout

            # Use 127.0.0.1 only for actual local connections
            ip_to_connect = '127.0.0.1' if target.ip_address in ['127.0.0.1', 'localhost'] else target.ip_address
            print(f"Connecting to agent at {ip_to_connect}:23033")
            s.connect((ip_to_connect, 23033))

            # Send the command with page parameter if provided
            req_id = 1
            payload = f"page={page}" if page else ""
            payload_bytes = payload.encode() if payload else b""
            header = build_request_header(0x01, req_id, CMD_GET_RUNNING_PROCESSES, len(payload_bytes))
            s.sendall(header + payload_bytes)

            # Receive the response header
            response_header = s.recv(HEADER_SIZE)
            # Parse header to get flags and payload_len
            _, _, flags, _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, response_header)

            # Check if the response is compressed
            is_compressed = (flags & FLAG_COMPRESSED) != 0

            # Receive the response payload
            s.settimeout(60)  # 60 second timeout for receiving data
            response_payload = b""
            remaining = payload_len

            while remaining > 0:
                chunk = s.recv(min(4096, remaining))
                if not chunk:
                    break
                response_payload += chunk
                remaining -= len(chunk)

            s.close()

            # Decompress if needed and decode the response
            if is_compressed:
                decompressed_payload = zlib.decompress(response_payload)
                process_data = decompressed_payload.decode('utf-8', errors='ignore')
            else:
                process_data = response_payload.decode('utf-8', errors='ignore')

            # Store the result
            scan_result = ScanResult.objects.create(
                target=target,
                scan_type="Running Processes",
                result_data=process_data,
                scan_time=timezone.now()
            )

            # Update the target's last scan time
            target.last_scan = timezone.now()
            target.save()

            # Don't show a success message for process data retrieval
            # This prevents cluttering the UI with too many notifications

        except Exception as e:
            messages.error(request, f'Error retrieving process data: {str(e)}')

    context = {
        'targets': targets,
        'selected_target': target,
        'process_data': process_data,
        'page_title': 'Running Processes'
    }
    return render(request, 'scanner/processes.html', context)

@login_required
def get_processes_data(request):
    """AJAX endpoint to get process data for a target"""
    target_id = request.GET.get('target_id')
    page = request.GET.get('page')

    if not target_id:
        return JsonResponse({'error': 'No target specified'}, status=400)

    target = get_object_or_404(Target, pk=target_id)

    try:
        # Send command to get process data
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)  # 30 second timeout

        # Use 127.0.0.1 only for actual local connections
        ip_to_connect = '127.0.0.1' if target.ip_address in ['127.0.0.1', 'localhost'] else target.ip_address
        print(f"Connecting to agent at {ip_to_connect}:23033")
        s.connect((ip_to_connect, 23033))

        # Send the command with page parameter if provided
        req_id = 1
        payload = f"page={page}" if page else ""
        payload_bytes = payload.encode() if payload else b""
        header = build_request_header(0x01, req_id, CMD_GET_RUNNING_PROCESSES, len(payload_bytes))
        s.sendall(header + payload_bytes)

        # Receive the response header
        response_header = s.recv(HEADER_SIZE)
        # Parse header to get flags and payload_len
        _, _, flags, _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, response_header)

        # Check if the response is compressed
        is_compressed = (flags & FLAG_COMPRESSED) != 0

        # Receive the response payload
        s.settimeout(60)  # 60 second timeout for receiving data
        response_payload = b""
        remaining = payload_len

        while remaining > 0:
            chunk = s.recv(min(4096, remaining))
            if not chunk:
                break
            response_payload += chunk
            remaining -= len(chunk)

        s.close()

        # Decompress if needed and decode the response
        if is_compressed:
            decompressed_payload = zlib.decompress(response_payload)
            process_data = decompressed_payload.decode('utf-8', errors='ignore')
        else:
            process_data = response_payload.decode('utf-8', errors='ignore')

        # Store the result
        ScanResult.objects.create(
            target=target,
            scan_type="Running Processes",
            result_data=process_data,
            scan_time=timezone.now()
        )

        # Update the target's last scan time
        target.last_scan = timezone.now()
        target.save()

        # Return the HTML data directly without showing a notification
        return JsonResponse({'html': process_data})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def analyze_process(request):
    """Analyze memory protection features of a process."""
    target_id = request.GET.get('target_id')
    pid = request.GET.get('pid')
    task_id = request.GET.get('task_id')
    start = request.GET.get('start', 'false').lower() == 'true'

    # Dictionary to store active analysis tasks
    if not hasattr(analyze_process, 'active_tasks'):
        analyze_process.active_tasks = {}

    # If we're checking status of an existing task
    if task_id:
        if task_id not in analyze_process.active_tasks:
            return JsonResponse({'error': 'Task not found'}, status=404)

        task = analyze_process.active_tasks[task_id]

        # If task is complete, return the result and clean up
        if task.get('complete'):
            html_output = task.get('html_output', '')
            # Clean up the task
            if task_id in analyze_process.active_tasks:
                del analyze_process.active_tasks[task_id]
            return JsonResponse({'complete': True, 'html': html_output})

        # Return current progress
        return JsonResponse({
            'complete': False,
            'progress': task.get('progress', 0),
            'status': task.get('status', 'Processing...')
        })

    # Validate parameters for starting a new analysis
    if not target_id:
        return JsonResponse({'error': 'No target specified'}, status=400)

    if not pid:
        return JsonResponse({'error': 'No process ID specified'}, status=400)

    try:
        pid = int(pid)
    except ValueError:
        return JsonResponse({'error': 'Invalid process ID'}, status=400)

    target = get_object_or_404(Target, pk=target_id)

    # Generate a unique task ID
    import uuid
    new_task_id = str(uuid.uuid4())

    # Initialize task data
    analyze_process.active_tasks[new_task_id] = {
        'target_id': target_id,
        'pid': pid,
        'start_time': timezone.now(),
        'progress': 0,
        'status': 'Initializing analysis...',
        'complete': False
    }

    # If this is just a request to start the task, return the task ID
    if start:
        # Start the analysis in a background thread
        import threading
        thread = threading.Thread(
            target=perform_process_analysis,
            args=(new_task_id, target, pid)
        )
        thread.daemon = True
        thread.start()

        return JsonResponse({'task_id': new_task_id})

    # If we get here, something went wrong with the request parameters
    return JsonResponse({'error': 'Invalid request parameters'}, status=400)

def perform_process_analysis(task_id, target, pid):
    """Perform the actual process analysis in a background thread."""
    try:
        # Update task status
        analyze_process.active_tasks[task_id]['status'] = 'Connecting to agent...'
        analyze_process.active_tasks[task_id]['progress'] = 5

        # Check if the target is the local machine (only localhost and actual local IP)
        local_ips = ['127.0.0.1', 'localhost']
        try:
            local_ips.append(socket.gethostbyname(socket.gethostname()))
        except:
            pass
        is_local = target.ip_address in local_ips

        if is_local:
            # For local machine, perform analysis directly
            analyze_process.active_tasks[task_id]['status'] = 'Analyzing process locally...'
            analyze_process.active_tasks[task_id]['progress'] = 10

            analyzer = MemoryProtectionCheck(pid)

            # Update progress as we go
            analyze_process.active_tasks[task_id]['status'] = 'Enumerating loaded modules...'
            analyze_process.active_tasks[task_id]['progress'] = 30

            analyzer.analyze()

            analyze_process.active_tasks[task_id]['status'] = 'Generating report...'
            analyze_process.active_tasks[task_id]['progress'] = 90

            # Generate HTML report and wrap it in a memory-protection-container div
            html_output = f'<div class="memory-protection-container">{analyzer.generate_html_report()}</div>'
        else:
            # For remote targets, send command to the agent
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60)  # 60 second timeout

            # Use 127.0.0.1 only for actual local connections
            ip_to_connect = '127.0.0.1' if target.ip_address in ['127.0.0.1', 'localhost'] else target.ip_address
            print(f"Connecting to agent at {ip_to_connect}:23033 for memory protection analysis")

            analyze_process.active_tasks[task_id]['status'] = f'Connecting to agent at {ip_to_connect}...'
            analyze_process.active_tasks[task_id]['progress'] = 10

            s.connect((ip_to_connect, 23033))

            analyze_process.active_tasks[task_id]['status'] = 'Sending analysis request to agent...'
            analyze_process.active_tasks[task_id]['progress'] = 20

            # Send the command with PID as payload
            req_id = 1
            payload = str(pid).encode()
            header = struct.pack(
                HEADER_FORMAT,
                MAGIC_HEADER,
                0x01,  # version
                0,     # flags
                req_id,
                CMD_ANALYZE_PROCESS_MEMORY,
                len(payload),
                0      # reserved
            )

            # Send header and payload
            s.sendall(header + payload)

            analyze_process.active_tasks[task_id]['status'] = 'Agent is analyzing process security...'
            analyze_process.active_tasks[task_id]['progress'] = 30

            # Receive the response header
            response_header = s.recv(HEADER_SIZE)
            # Parse header to get flags and payload_len
            _, _, flags, _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, response_header)

            # Check if the response is compressed
            is_compressed = (flags & FLAG_COMPRESSED) != 0

            analyze_process.active_tasks[task_id]['status'] = 'Receiving analysis results...'
            analyze_process.active_tasks[task_id]['progress'] = 50

            # Receive the response payload
            s.settimeout(120)  # 2 minute timeout for receiving data
            response_payload = b""
            remaining = payload_len

            # Track progress of data reception
            total_received = 0

            while remaining > 0:
                chunk = s.recv(min(4096, remaining))
                if not chunk:
                    break
                response_payload += chunk
                total_received += len(chunk)
                remaining -= len(chunk)

                # Update progress based on data received
                if payload_len > 0:
                    receive_progress = int((total_received / payload_len) * 40)  # 40% of progress for receiving
                    analyze_process.active_tasks[task_id]['progress'] = 50 + receive_progress
                    analyze_process.active_tasks[task_id]['status'] = f'Receiving analysis data: {int(total_received / payload_len * 100)}%'

            s.close()

            analyze_process.active_tasks[task_id]['status'] = 'Processing analysis results...'
            analyze_process.active_tasks[task_id]['progress'] = 90

            # Decompress if needed and decode the response
            if is_compressed:
                decompressed_payload = zlib.decompress(response_payload)
                decoded_output = decompressed_payload.decode('utf-8', errors='ignore')
            else:
                decoded_output = response_payload.decode('utf-8', errors='ignore')

            # Wrap the output in a memory-protection-container div
            html_output = f'<div class="memory-protection-container">{decoded_output}</div>'

            # Check if the response is an error message
            if html_output.startswith('Error:'):
                raise Exception(html_output)

        # Store the result
        ScanResult.objects.create(
            target=target,
            scan_type=f"Memory Protection Analysis (PID: {pid})",
            result_data=html_output,
            scan_time=timezone.now()
        )

        # Update the target's last scan time
        target.last_scan = timezone.now()
        target.save()

        # Mark task as complete and store the result
        analyze_process.active_tasks[task_id]['status'] = 'Analysis complete'
        analyze_process.active_tasks[task_id]['progress'] = 100
        analyze_process.active_tasks[task_id]['complete'] = True
        analyze_process.active_tasks[task_id]['html_output'] = html_output

    except Exception as e:
        error_message = str(e)
        logger.error(f"Error analyzing process {pid}: {error_message}")

        html_output = f"""
        <div class="memory-protection-container">
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle mr-2"></i>
                <strong>Error Analyzing Process</strong>
                <p>{error_message}</p>
                <p class="mb-0">This may be due to insufficient permissions or the process no longer exists.</p>
            </div>
        </div>
        """

        # Mark task as complete with error
        analyze_process.active_tasks[task_id]['status'] = 'Error: ' + error_message
        analyze_process.active_tasks[task_id]['progress'] = 100
        analyze_process.active_tasks[task_id]['complete'] = True
        analyze_process.active_tasks[task_id]['html_output'] = html_output

@login_required
def network_info(request):
    """Network Information page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')
    devices = NetworkDevice.objects.all().order_by('-last_seen')

    # Get list of target IPs for template
    target_ips = [target.ip_address for target in targets]

    context = {
        'targets': targets,
        'devices': devices,
        'target_ips': target_ips,
        'page_title': 'Network Information'
    }
    return render(request, 'scanner/network_info.html', context)

@login_required
def target_detail(request, target_id):
    """Target detail page"""
    target = get_object_or_404(Target, pk=target_id)
    scan_results = target.scan_results.all().order_by('-scan_time')[:10]

    context = {
        'target': target,
        'scan_results': scan_results,
        'page_title': f'Target: {target.ip_address}'
    }
    return render(request, 'scanner/target_detail.html', context)

@login_required
def add_target(request):
    """Add a new target"""
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        hostname = request.POST.get('hostname', '')
        description = request.POST.get('description', '')

        # Validate IP address
        try:
            socket.inet_aton(ip_address)
            # Check if target already exists
            if Target.objects.filter(ip_address=ip_address).exists():
                messages.error(request, f'Target with IP {ip_address} already exists')
                return redirect('scanner:index')

            # Create new target
            target = Target.objects.create(
                ip_address=ip_address,
                hostname=hostname,
                description=description
            )
            messages.success(request, f'Target {ip_address} added successfully')
            return redirect('scanner:target_detail', target_id=target.id)
        except:
            messages.error(request, f'Invalid IP address: {ip_address}')
            return redirect('scanner:index')

    return render(request, 'scanner/add_target.html', {'page_title': 'Add Target'})

@login_required
def scan_network(request):
    """Scan the local network for devices"""
    if request.method == 'POST':
        try:
            # Perform ARP scan
            devices = arp_scan(verbose=False)

            # Update or create devices in the database
            for device in devices:
                NetworkDevice.objects.update_or_create(
                    ip_address=device['ip'],
                    mac_address=device['mac'],
                    defaults={
                        'vendor': device['vendor'],
                        'last_seen': timezone.now()
                    }
                )

            messages.success(request, f'Found {len(devices)} devices on the network')
        except Exception as e:
            messages.error(request, f'Error scanning network: {str(e)}')

    return redirect('scanner:network_info')

@login_required
def send_command(request, target_id, command_code):
    """Send a command to a target and store the result"""
    target = get_object_or_404(Target, pk=target_id)

    # Define timeout values based on command complexity
    # Commands 4 (SYSTEM_DIAG) and 5 (FULL_OS_INFO) need longer timeouts
    connection_timeout = 15  # Default connection timeout in seconds
    receive_timeout = 60     # Default receive timeout in seconds
    max_retries = 2          # Number of connection retries

    # Adjust timeouts for complex commands
    if command_code in [CMD_SYSTEM_DIAG, CMD_FULL_OS_INFO, CMD_FULL_NETWORK_INFO]:
        connection_timeout = 30
        receive_timeout = 120  # 2 minutes for complex commands

    try:
        # Get command name for display
        command_name = "Unknown Command"
        for name, value in globals().items():
            if name.startswith('CMD_') and value == command_code:
                command_name = name.replace('CMD_', '').replace('_', ' ').title()

        # Connection with retry logic
        s = None
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                print(f"Connection attempt {attempt + 1} for {target.ip_address}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(connection_timeout)
                s.connect((target.ip_address, 23033))
                break  # Connection successful, exit retry loop
            except (socket.timeout, ConnectionRefusedError) as e:
                last_exception = e
                if s:
                    s.close()
                if attempt < max_retries:
                    print(f"Retrying connection to {target.ip_address} ({attempt + 1}/{max_retries})")
                    time.sleep(2)  # Wait 2 seconds before retrying
                else:
                    # All retries failed
                    raise last_exception

        # Send the command
        req_id = 1
        header = build_request_header(0x01, req_id, command_code, 0)
        s.sendall(header)

        # Receive the response header
        response_header = s.recv(HEADER_SIZE)
        # Parse header to get flags and payload_len
        _, _, flags, _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, response_header)

        # Check if the response is compressed
        is_compressed = (flags & FLAG_COMPRESSED) != 0
        if is_compressed:
            print(f"Response is compressed. Expecting {payload_len} bytes of compressed data.")

        # Configure socket for better reliability
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # On Windows, we can set TCP keepalive parameters
        if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
            # Set keepalive parameters (enable, idle time in ms, interval in ms)
            s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))

        # Receive the response payload with a longer timeout for large responses
        s.settimeout(receive_timeout)
        response_payload = b""
        remaining = payload_len
        max_retries = 3

        try:
            print(f"Receiving {payload_len} bytes from {target.ip_address} for command {command_name}")
            chunk_size = 4096  # 4KB chunks (smaller for better reliability)

            # Add progress tracking
            total_received = 0
            last_progress = 0
            retry_count = 0
            last_received_time = time.time()

            while remaining > 0:
                try:
                    chunk = s.recv(min(chunk_size, remaining))

                    if not chunk:
                        # No data received, check if we should retry
                        if retry_count < max_retries:
                            retry_count += 1
                            print(f"No data received, retrying ({retry_count}/{max_retries})...")
                            time.sleep(1)
                            continue
                        else:
                            print(f"Connection closed with {remaining} bytes remaining after {max_retries} retries")
                            break

                    # Reset retry count on successful receive
                    retry_count = 0
                    last_received_time = time.time()

                    response_payload += chunk
                    total_received += len(chunk)
                    remaining -= len(chunk)

                    # Log progress at 25%, 50%, 75% and 100%
                    progress = int((total_received / payload_len) * 100)
                    if progress >= last_progress + 25:
                        print(f"Progress: {progress}% - Received {total_received} of {payload_len} bytes")
                        last_progress = progress

                except socket.timeout:
                    # Handle timeout during receive
                    current_time = time.time()
                    elapsed = current_time - last_received_time

                    if retry_count < max_retries:
                        retry_count += 1
                        print(f"Timeout after {elapsed:.1f}s, retrying ({retry_count}/{max_retries})...")
                        # Reduce timeout for subsequent retries
                        s.settimeout(max(5, receive_timeout // 2))
                        continue
                    else:
                        print(f"Socket timeout after {max_retries} retries, got {len(response_payload)} of {payload_len} bytes")
                        break

        except socket.timeout:
            print(f"Initial socket timeout while receiving data, got {len(response_payload)} of {payload_len} bytes")
            # Continue with partial data if we have some
            if not response_payload:
                raise
        except Exception as e:
            print(f"Error receiving data: {e}")
            if not response_payload:
                raise
        finally:
            s.close()

        # Check if we received all the expected data
        data_completeness = len(response_payload) / payload_len * 100
        print(f"Received {len(response_payload)} of {payload_len} bytes ({data_completeness:.1f}% complete)")

        # Decompress if needed and decode the response
        if is_compressed:
            try:
                print(f"Decompressing {len(response_payload)} bytes of data")
                decompressed_payload = zlib.decompress(response_payload)
                print(f"Decompressed to {len(decompressed_payload)} bytes")
                result_data = decompressed_payload.decode('utf-8', errors='ignore')
            except zlib.error as e:
                print(f"Error decompressing data: {e}")
                # Try to decode the compressed data as a fallback
                result_data = response_payload.decode('utf-8', errors='ignore')

                # If it's HTML content that was truncated, add a warning
                if result_data.startswith('<!DOCTYPE html>') or result_data.startswith('<html>'):
                    result_data = result_data.replace('</body>', f'''
                        <div class="alert alert-warning">
                            <strong>Warning:</strong> Only {data_completeness:.1f}% of the data was received.
                            Some information may be missing or incomplete.
                        </div>
                        </body>
                    ''')
        else:
            result_data = response_payload.decode('utf-8', errors='ignore')

            # If it's partial text data, add a note
            if data_completeness < 99:
                result_data += f"\n\n[Note: Only {data_completeness:.1f}% of the data was received. Some information may be missing.]"

        # Store the result
        scan_result = ScanResult.objects.create(
            target=target,
            scan_type=command_name,
            result_data=result_data,
            scan_time=timezone.now()
        )

        # Update the target's last scan time
        target.last_scan = timezone.now()
        target.save()

        # Don't show a success message for every command
        # This prevents cluttering the UI with too many notifications

        # Format the result data for professional display
        formatted_data = format_command_output(result_data, command_name)

        # Return the result
        return JsonResponse({
            'status': 'success',
            'result_id': scan_result.id,
            'result_data': formatted_data
        })

    except socket.timeout:
        error_msg = f'Connection to {target.ip_address} timed out'
        print(f"Error: {error_msg}")
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

    except ConnectionRefusedError:
        error_msg = f'Connection to {target.ip_address} refused. Make sure the agent is running.'
        print(f"Error: {error_msg}")
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

    except Exception as e:
        import traceback
        error_msg = f'Error: {str(e)}'
        print(f"Unexpected error: {error_msg}")
        print(traceback.format_exc())
        messages.error(request, error_msg)
        return JsonResponse({
            'status': 'error',
            'message': error_msg
        }, status=500)

@login_required
def get_scan_result(request, result_id):
    """Get a specific scan result"""
    # request parameter is required by Django's URL routing
    result = get_object_or_404(ScanResult, pk=result_id)

    # Format the result data for professional display
    formatted_data = format_command_output(result.result_data, result.scan_type)

    return JsonResponse({
        'id': result.id,
        'target': result.target.ip_address,
        'scan_type': result.scan_type,
        'scan_time': result.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
        'result_data': formatted_data
    })

@login_required
def delete_target(request, target_id):
    """Delete a target"""
    if request.method == 'POST':
        target = get_object_or_404(Target, pk=target_id)
        ip = target.ip_address
        target.delete()
        messages.success(request, f'Target {ip} deleted successfully')

    return redirect('scanner:index')

@login_required
def clear_network_devices(request):
    """Clear all network devices from the database"""
    if request.method == 'POST':
        # Count devices before deletion
        count = NetworkDevice.objects.count()

        # Delete all network devices
        NetworkDevice.objects.all().delete()

        messages.success(request, f'Successfully cleared {count} network devices')

    return redirect('scanner:network_info')
