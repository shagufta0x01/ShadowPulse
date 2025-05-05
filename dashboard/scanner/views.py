from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.contrib import messages
import socket
import struct
import sys
import os
import zlib
import time
from .utils import format_command_output

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

def index(request):
    """Dashboard home page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')
    devices = NetworkDevice.objects.all().order_by('-last_seen')[:10]

    # Get list of target IPs for template
    target_ips = [target.ip_address for target in targets]

    context = {
        'targets': targets,
        'devices': devices,
        'target_ips': target_ips,
        'page_title': 'Dashboard'
    }
    return render(request, 'scanner/index.html', context)

def os_info(request):
    """OS Information page"""
    targets = Target.objects.filter(is_active=True).order_by('-last_scan')

    # Group sections by category
    sections_by_category = {}
    for section in OS_INFO_SECTIONS:
        category = section.get('category', 'Uncategorized')
        if category not in sections_by_category:
            sections_by_category[category] = []
        sections_by_category[category].append(section)

    context = {
        'targets': targets,
        'sections': OS_INFO_SECTIONS,
        'sections_by_category': sections_by_category,
        'page_title': 'OS Information'
    }
    return render(request, 'scanner/os_info.html', context)

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

        messages.success(request, f'Successfully retrieved {section_name} from {target.ip_address}')

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

        messages.success(request, f'Successfully ran {command_name} on {target.ip_address}')

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

def delete_target(request, target_id):
    """Delete a target"""
    if request.method == 'POST':
        target = get_object_or_404(Target, pk=target_id)
        ip = target.ip_address
        target.delete()
        messages.success(request, f'Target {ip} deleted successfully')

    return redirect('scanner:index')
