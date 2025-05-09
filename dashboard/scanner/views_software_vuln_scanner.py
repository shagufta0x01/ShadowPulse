"""
Views for software vulnerability scanning functionality.
"""

import logging
import time
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from .models import Target, InstalledSoftware, SoftwareVulnerabilityScan, SoftwareVulnerability
from .software_vulnerability_scanner import create_software_vuln_scanner, get_software_vuln_scanner, SoftwareVulnerabilityScanner

# Configure logging
logger = logging.getLogger(__name__)

@login_required
def software_vuln_scan_home(request):
    """
    Display the software vulnerability scanning home page.
    """
    # Get all targets
    targets = Target.objects.filter(is_active=True).order_by('ip_address')

    # Get recent scans
    recent_scans = SoftwareVulnerabilityScan.objects.all().order_by('-start_time')[:10]

    # Get vulnerability statistics
    total_vulnerabilities = SoftwareVulnerability.objects.count()
    high_vulnerabilities = SoftwareVulnerability.objects.filter(severity__in=['critical', 'high']).count()
    medium_vulnerabilities = SoftwareVulnerability.objects.filter(severity='medium').count()
    low_vulnerabilities = SoftwareVulnerability.objects.filter(severity__in=['low', 'unknown']).count()

    context = {
        'page_title': 'Software Vulnerability Scanner',
        'targets': targets,
        'recent_scans': recent_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'high_vulnerabilities': high_vulnerabilities,
        'medium_vulnerabilities': medium_vulnerabilities,
        'low_vulnerabilities': low_vulnerabilities
    }

    return render(request, 'scanner/software_vuln_scan_home.html', context)

@login_required
def start_software_vuln_scan(request, target_id):
    """
    Start a software vulnerability scan for a target.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method is allowed'})

    try:
        # Get the target
        target = get_object_or_404(Target, id=target_id)

        # Create a new scan record
        scan = SoftwareVulnerabilityScan.objects.create(
            target=target,
            status='pending'
        )

        # Create a process ID for state management
        process_id = f"software_vuln_scan_{scan.id}"

        # Create and start the scanner
        scanner = create_software_vuln_scanner(target_id, scan.id)
        success = scanner.start_scan(process_id)

        if success:
            return JsonResponse({
                'status': 'success',
                'message': f'Software vulnerability scan started for {target}',
                'scan_id': scan.id,
                'process_id': process_id
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to start scan. Another scan might be in progress.'
            })

    except Exception as e:
        logger.error(f"Error starting software vulnerability scan: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': f'Error: {str(e)}'
        })

@login_required
def software_vuln_scan_status(request):
    """
    Get the status of a software vulnerability scan.
    """
    process_id = request.GET.get('process_id')

    if not process_id:
        return JsonResponse({
            'running': False,
            'progress': 0,
            'status_message': 'No process ID provided',
            'completed': False,
            'failed': True,
            'error': 'No process ID provided'
        })

    # Extract scan ID from process ID
    try:
        scan_id = int(process_id.split('_')[-1])
    except (ValueError, IndexError):
        return JsonResponse({
            'running': False,
            'progress': 0,
            'status_message': 'Invalid process ID format',
            'completed': False,
            'failed': True,
            'error': 'Invalid process ID format'
        })

    # Try to get the scanner
    scanner = get_software_vuln_scanner(scan_id)

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

        # Always include status message for progress bar
        response_data.update({
            'status_message': data.get('status_message', 'Processing...')
        })

        # Add additional data if not minimal request
        if not minimal:
            response_data.update({
                'vulnerabilities_found': data.get('vulnerabilities_found', 0),
                'error': data.get('error', '')
            })

        return JsonResponse(response_data)

    # If not found in state manager, return default status
    return JsonResponse({
        'running': False,
        'progress': 0,
        'status_message': 'Scan not found or completed',
        'completed': False,
        'failed': False
    })

@login_required
def stop_software_vuln_scan(request, scan_id):
    """
    Stop a running software vulnerability scan.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method is allowed'})

    try:
        # Get the scan
        scan = get_object_or_404(SoftwareVulnerabilityScan, id=scan_id)

        # Try to get the scanner
        scanner = get_software_vuln_scanner(scan_id)

        if scanner:
            # Stop the scanner
            success = scanner.stop_scan()

            if success:
                return JsonResponse({
                    'status': 'success',
                    'message': 'Scan stopped successfully'
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Failed to stop scan'
                })

        # If scanner not found, update the scan record directly
        scan.status = 'cancelled'
        scan.end_time = timezone.now()
        scan.save()

        # Unregister the process if it exists
        from .state_manager import unregister_process

        process_id = f"software_vuln_scan_{scan_id}"
        unregister_process(process_id)

        return JsonResponse({
            'status': 'success',
            'message': 'Scan marked as cancelled'
        })

    except Exception as e:
        logger.error(f"Error stopping software vulnerability scan: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': f'Error: {str(e)}'
        })

@login_required
def software_vuln_scan_results(request, scan_id):
    """
    Display the results of a software vulnerability scan.
    """
    # Get the scan
    scan = get_object_or_404(SoftwareVulnerabilityScan, id=scan_id)

    # Get vulnerabilities
    vulnerabilities = SoftwareVulnerability.objects.filter(scan=scan).order_by('-severity', '-cvss_score')

    # Group vulnerabilities by software and calculate severity counts
    software_vulnerabilities = {}
    software_severity_counts = {}

    for vuln in vulnerabilities:
        software_name = vuln.software.name

        # Initialize if not exists
        if software_name not in software_vulnerabilities:
            software_vulnerabilities[software_name] = []
            software_severity_counts[software_name] = {
                'high': 0,
                'medium': 0,
                'low': 0
            }

        # Add vulnerability to list
        software_vulnerabilities[software_name].append(vuln)

        # Count by severity
        if vuln.severity in ['critical', 'high']:
            software_severity_counts[software_name]['high'] += 1
        elif vuln.severity == 'medium':
            software_severity_counts[software_name]['medium'] += 1
        else:  # low or unknown
            software_severity_counts[software_name]['low'] += 1

    # Create process_id for in-progress scans
    process_id = None
    if scan.status == 'in_progress':
        process_id = f"software_vuln_scan_{scan.id}"

    context = {
        'page_title': f'Software Vulnerability Scan Results - {scan.target}',
        'scan': scan,
        'vulnerabilities': vulnerabilities,
        'software_vulnerabilities': software_vulnerabilities,
        'software_severity_counts': software_severity_counts,
        'process_id': process_id
    }

    return render(request, 'scanner/software_vuln_scan_results.html', context)

@login_required
def installed_software_list(request, target_id):
    """
    Display the list of installed software for a target.
    If no software is found, attempt to fetch it from the agent.
    """
    # Get the target
    target = get_object_or_404(Target, id=target_id)

    # Check if we need to refresh the data
    refresh = request.GET.get('refresh', 'false').lower() == 'true'

    # Get installed software
    software = InstalledSoftware.objects.filter(target=target).order_by('name')

    # If no software found or refresh requested, try to fetch from agent
    fetching = False
    fetch_error = None
    if (not software.exists() or refresh) and target.is_active:
        fetching = True
        try:
            # Try to get installed software directly from the agent
            # Instead of using get_os_info_section, we'll implement the core functionality here
            from .models import ScanResult
            from django.utils import timezone
            import socket
            import struct
            import zlib

            # Import constants from views
            from .views import HEADER_FORMAT, MAGIC_HEADER, CMD_GET_OS_INFO_SECTION, HEADER_SIZE, FLAG_COMPRESSED

            # Define timeout values
            connection_timeout = 15
            receive_timeout = 60
            max_retries = 2

            # Connection with retry logic
            s = None
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    logger.info(f"Connection attempt {attempt + 1} for {target.ip_address}")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(connection_timeout)
                    s.connect((target.ip_address, 23033))
                    break  # Connection successful, exit retry loop
                except (socket.timeout, ConnectionRefusedError) as e:
                    last_exception = e
                    if s:
                        s.close()
                    if attempt < max_retries:
                        logger.info(f"Retrying connection to {target.ip_address} ({attempt + 1}/{max_retries})")
                        time.sleep(2)  # Wait 2 seconds before retrying
                    else:
                        # All retries failed
                        raise last_exception

            # Send the command with the section ID as payload
            req_id = 1
            payload = f"installed_software:{target.ip_address}".encode()
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
                logger.info(f"Response is compressed. Expecting {payload_len} bytes of compressed data.")

            # Configure socket for better reliability
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # Receive the response payload
            s.settimeout(receive_timeout)
            response_payload = b""
            remaining = payload_len

            try:
                logger.info(f"Receiving {payload_len} bytes from {target.ip_address} for installed software")
                chunk_size = 4096  # 4KB chunks

                # Add progress tracking
                total_received = 0
                last_progress = 0

                while remaining > 0:
                    chunk = s.recv(min(chunk_size, remaining))
                    if not chunk:
                        logger.info(f"Connection closed with {remaining} bytes remaining")
                        break
                    response_payload += chunk
                    total_received += len(chunk)
                    remaining -= len(chunk)

                    # Log progress at 25%, 50%, 75% and 100%
                    progress = int((total_received / payload_len) * 100)
                    if progress >= last_progress + 25:
                        logger.info(f"Progress: {progress}% - Received {total_received} of {payload_len} bytes")
                        last_progress = progress
            except socket.timeout:
                logger.error(f"Socket timeout while receiving data, got {len(response_payload)} of {payload_len} bytes")
                # Continue with partial data if we have some
                if not response_payload:
                    raise
            finally:
                s.close()

            # Decompress if needed and decode the response
            if is_compressed:
                try:
                    logger.info(f"Decompressing {len(response_payload)} bytes of data")
                    decompressed_payload = zlib.decompress(response_payload)
                    logger.info(f"Decompressed to {len(decompressed_payload)} bytes")
                    result_data = decompressed_payload.decode('utf-8', errors='ignore')
                except zlib.error as e:
                    logger.error(f"Error decompressing data: {e}")
                    # Try to decode the compressed data as a fallback
                    result_data = response_payload.decode('utf-8', errors='ignore')
            else:
                result_data = response_payload.decode('utf-8', errors='ignore')

            # Store the result
            ScanResult.objects.create(
                target=target,
                scan_type="Section: Installed Software",
                result_data=result_data,
                scan_time=timezone.now()
            )

            # Update the target's last scan time
            target.last_scan = timezone.now()
            target.save()

            # Now parse the installed software data
            scanner = SoftwareVulnerabilityScanner(target_id)

            # Parse based on OS type
            if "Windows" in result_data:
                software_list = scanner._parse_windows_installed_software(result_data)
            else:
                software_list = scanner._parse_linux_installed_software(result_data)

            logger.info(f"Parsed {len(software_list)} software items from scan result")

            # Save software to database
            for sw in software_list:
                _, created = InstalledSoftware.objects.update_or_create(
                    target=target,
                    name=sw['name'],
                    version=sw.get('version'),
                    defaults={
                        'vendor': sw.get('vendor'),
                        'install_date': sw.get('install_date'),
                        'install_location': sw.get('install_location'),
                        'last_checked': timezone.now()
                    }
                )
                if created:
                    logger.info(f"Created new software: {sw['name']} {sw.get('version')}")

            # Log success
            logger.info(f"Successfully fetched installed software for target {target_id}")

            # Refresh the software list
            software = InstalledSoftware.objects.filter(target=target).order_by('name')
            logger.info(f"Found {software.count()} software items in database")

            fetching = False
        except Exception as e:
            # If there was an exception, set the fetch_error
            logger.error(f"Error in installed_software_list: {str(e)}", exc_info=True)
            fetch_error = str(e)
            fetching = False

    # Get vulnerability counts
    vulnerable_software = software.filter(is_vulnerable=True).count()

    context = {
        'page_title': f'Installed Software - {target}',
        'target': target,
        'software': software,
        'total_software': software.count(),
        'vulnerable_software': vulnerable_software,
        'fetching': fetching,
        'fetch_error': fetch_error,
        'refresh': refresh
    }

    return render(request, 'scanner/installed_software_list.html', context)

@login_required
def software_vulnerability_detail(request, vuln_id):
    """
    Display details of a specific software vulnerability.
    """
    # Get the vulnerability
    vulnerability = get_object_or_404(SoftwareVulnerability, id=vuln_id)

    context = {
        'page_title': f'Vulnerability Detail - {vulnerability.cve_id or vulnerability.title}',
        'vulnerability': vulnerability
    }

    return render(request, 'scanner/software_vulnerability_detail.html', context)
