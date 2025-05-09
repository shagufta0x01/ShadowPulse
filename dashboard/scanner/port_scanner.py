"""
Port Scanner Module

This module provides comprehensive port scanning capabilities using nmap when available,
with a fallback to a custom implementation. It includes service detection, version
identification, and OS fingerprinting.
"""

import socket
import struct
import threading
import time
import re
import json
import logging
import os
import importlib.util
import subprocess
import shutil
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from .models import Target, PortScanResult, PortInfo

# Configure logging
logger = logging.getLogger(__name__)

# Check if nmap binary is available
NMAP_PATH = shutil.which('nmap')
if NMAP_PATH:
    logger.info(f"nmap binary found at {NMAP_PATH}")
else:
    logger.warning("nmap binary not found, will attempt to use python-nmap or fall back to custom implementation")

# Common service definitions
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Service fingerprints
SERVICE_FINGERPRINTS = {
    "SSH": rb"SSH-\d\.\d",
    "FTP": rb"220.*FTP",
    "SMTP": rb"220.*SMTP",
    "HTTP": rb"HTTP/\d\.\d",
    "POP3": rb"\+OK",
    "IMAP": rb"\* OK",
    "TELNET": rb"^\xff\xfb|\xff\xfd",
    "RDP": rb"^\x03\x00",
    "MySQL": rb"^\x5b\x00\x00\x00\x0a",
    "SMB": rb"^\x00\x00\x00\x85",
    "DNS": rb"^\x00\x00\x84\x00\x00\x00\x00\x01"
}

# Service probes for active fingerprinting
SERVICE_PROBES = {
    "HTTP": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "FTP": b"",  # FTP servers usually send banner automatically
    "SSH": b"",  # SSH servers usually send banner automatically
    "SMTP": b"EHLO localhost\r\n",
    "POP3": b"",  # POP3 servers usually send banner automatically
    "IMAP": b"A001 CAPABILITY\r\n",
    "TELNET": b"",  # Telnet servers usually send banner automatically
    "MySQL": b"\x0a\x00\x00\x00\x0a",
    "DNS": b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
}

class PortScanner:
    """
    Comprehensive port scanner with service detection capabilities.
    """

    def __init__(self, target, scan_type='standard', port_range=None, custom_nmap_args=None):
        """
        Initialize the port scanner.

        Args:
            target (Target): Target system to scan
            scan_type (str): Type of scan (quick, standard, comprehensive, custom)
            port_range (str): Custom port range to scan (e.g., "1-1024,3389,8080")
            custom_nmap_args (str): Custom nmap arguments for advanced scanning
        """
        self.target = target
        self.scan_type = scan_type
        self.custom_port_range = port_range
        self.custom_nmap_args = custom_nmap_args
        self.scan_result = None
        self.running = False
        self.scan_thread = None
        self.progress = 0
        self.status_message = "Initializing..."
        self.open_ports = {}
        self.start_time = None
        self.end_time = None
        self.scan_method = "unknown"  # Will be set to "nmap" or "builtin" during scanning

    def start_scan(self):
        """Start the port scanning process."""
        if self.running:
            return False

        # Create a new port scan result record
        self.scan_result = PortScanResult.objects.create(
            target=self.target,
            status='in_progress',
            scan_type=self.scan_type,
            port_range=self._get_port_range_str()
        )

        self.running = True
        self.progress = 0
        self.status_message = "Starting port scan..."
        self.start_time = timezone.now()

        # Register with state manager
        from . import state_manager
        process_id = f"port_scan_{self.scan_result.id}"
        state_manager.register_process(process_id, 'port_scan', {
            'scan_id': self.scan_result.id,
            'target_id': str(self.target.id),
            'scan_type': self.scan_type
        })

        # Start scan thread
        self.scan_thread = threading.Thread(target=self._run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

        # Register thread with state manager
        state_manager.register_thread(process_id, self.scan_thread)

        return True

    def stop_scan(self):
        """Stop the port scanning process."""
        if not self.running:
            return False

        self.running = False

        # Wait for thread to finish
        if self.scan_thread:
            self.scan_thread.join(timeout=2.0)

        # Update scan result status
        if self.scan_result:
            self.scan_result.status = 'cancelled'
            self.scan_result.end_time = timezone.now()
            self.scan_result.save()

            # Unregister from state manager
            from . import state_manager
            process_id = f"port_scan_{self.scan_result.id}"
            state_manager.unregister_process(process_id)

        return True

    def _get_port_range_str(self):
        """Get the port range string based on scan type or custom range."""
        if self.custom_port_range:
            return self.custom_port_range

        if self.scan_type == 'quick':
            return "21-23,25,53,80,443,3389,8080"
        elif self.scan_type == 'standard':
            return "1-1024"
        else:  # comprehensive
            return "1-65535"

    def _parse_port_range(self, port_range_str):
        """Parse a port range string into a list of ports."""
        ports = []

        # Split by comma
        for part in port_range_str.split(','):
            if '-' in part:
                # Handle range (e.g., 1-1024)
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                # Handle single port
                ports.append(int(part))

        return sorted(list(set(ports)))  # Remove duplicates and sort

    def _count_ports_in_range(self, port_range_str):
        """Count the number of ports in a range string without creating the full list."""
        count = 0

        # Split by comma
        for part in port_range_str.split(','):
            if '-' in part:
                # Handle range (e.g., 1-1024)
                start, end = part.split('-')
                count += (int(end) - int(start) + 1)
            else:
                # Handle single port
                count += 1

        return count

    def _run_scan(self):
        """Run the port scan in a separate thread."""
        try:
            # Get process ID for state manager
            from . import state_manager
            process_id = f"port_scan_{self.scan_result.id}"

            # Determine if we should use the agent for scanning
            use_agent = self._should_use_agent()

            # Update state manager with scan method
            state_manager.update_process_data(process_id, {
                'scan_method': 'agent' if use_agent else 'local',
                'progress': self.progress,
                'status_message': self.status_message
            })

            if use_agent:
                self._run_agent_scan()
            else:
                self._run_local_scan()

            # Finalize scan
            self.end_time = timezone.now()
            self.scan_result.status = 'completed'
            self.scan_result.end_time = self.end_time
            self.scan_result.duration = self.end_time - self.start_time
            self.scan_result.open_ports_count = len(self.open_ports)
            self.scan_result.save()

            self.status_message = f"Scan completed. Found {len(self.open_ports)} open ports."
            self.progress = 100

            # Update state manager with final status
            state_manager.update_process_data(process_id, {
                'progress': 100,
                'status_message': self.status_message,
                'open_ports_count': len(self.open_ports),
                'completed': True,
                'scan_method': self.scan_method
            })

        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            self.status_message = f"Scan failed: {str(e)}"

            # Update scan result status
            if self.scan_result:
                self.scan_result.status = 'failed'
                self.scan_result.end_time = timezone.now()
                self.scan_result.save()

            # Update state manager with error
            state_manager.update_process_data(process_id, {
                'progress': self.progress,
                'status_message': self.status_message,
                'error': str(e),
                'failed': True
            })

        finally:
            self.running = False

            # Unregister process after a delay to allow status to be read
            def delayed_unregister():
                import time
                time.sleep(60)  # Keep process info for 1 minute after completion
                state_manager.unregister_process(process_id)

            threading.Thread(target=delayed_unregister, daemon=True).start()

    def _should_use_agent(self):
        """Determine if we should use the agent for scanning."""
        # For port scanning, we always use local scanning
        # Port scanning doesn't need to communicate with an agent
        return False

    def _run_agent_scan(self):
        """Run the port scan using the agent."""
        self.status_message = "Connecting to agent..."
        self.progress = 5

        try:
            # Import the host controller module using direct import
            import os
            import importlib.util

            # Get the current directory
            current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

            # Import host_controller.py
            host_controller_path = os.path.join(current_dir, "proto", "host", "host_controller.py")
            self.status_message = f"Loading host controller module..."

            if os.path.exists(host_controller_path):
                spec = importlib.util.spec_from_file_location("host_controller", host_controller_path)
                host_controller = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(host_controller)
                send_command = host_controller.send_command
            else:
                raise ImportError(f"Host controller module not found at {host_controller_path}")

            # Import protocol.py
            protocol_path = os.path.join(current_dir, "proto", "pro", "protocol.py")
            self.status_message = f"Loading protocol module..."

            if os.path.exists(protocol_path):
                spec = importlib.util.spec_from_file_location("protocol", protocol_path)
                protocol = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(protocol)
                CMD_PORT_SCAN = protocol.CMD_PORT_SCAN
            else:
                raise ImportError(f"Protocol module not found at {protocol_path}")

            # Send the port scan command to the agent
            self.status_message = f"Sending port scan command to agent..."
            self.progress = 10

            # Prepare payload with scan parameters
            payload = json.dumps({
                'scan_type': self.scan_type,
                'port_range': self._get_port_range_str()
            })

            # Send the command
            response = send_command(self.target.ip_address, CMD_PORT_SCAN, payload, verbose=True)

            if not response:
                raise Exception("No response received from agent")

            # Parse the JSON response
            self.status_message = "Processing scan results from agent..."
            self.progress = 90

            # Handle both string and bytes responses
            if isinstance(response, bytes):
                response_str = response.decode('utf-8', errors='replace')
            else:
                response_str = response

            # Parse the JSON response
            scan_results = json.loads(response_str)

            # Process the results
            if scan_results.get('status') == 'completed':
                # Extract port information
                port_info_list = scan_results.get('ports', [])

                # Store port information
                for port_info in port_info_list:
                    port = port_info.get('port')
                    self.open_ports[port] = {
                        'service': port_info.get('service', 'unknown'),
                        'version': port_info.get('version', ''),
                        'banner': port_info.get('banner', '')
                    }

                    # Save port info to database
                    PortInfo.objects.create(
                        scan_result=self.scan_result,
                        port_number=port,
                        service_name=port_info.get('service', 'unknown'),
                        service_version=port_info.get('version', ''),
                        banner=port_info.get('banner', ''),
                        is_open=True
                    )
            else:
                # Scan failed
                error_message = scan_results.get('error', 'Unknown error')
                raise Exception(f"Agent scan failed: {error_message}")

        except (ImportError, ModuleNotFoundError):
            # Fall back to local scanning
            self.status_message = "Agent communication failed. Falling back to local scanning..."
            self._run_local_scan()

    def _run_local_scan(self):
        """Run the port scan locally."""
        self.status_message = "Starting local port scan..."
        self.progress = 5

        # Get port range string
        port_range_str = self._get_port_range_str()

        # Try to use nmap first
        try:
            self._run_nmap_scan(port_range_str)
        except Exception as e:
            logger.warning(f"Nmap scan failed: {str(e)}. Falling back to custom scanner.")
            self._run_custom_scan(port_range_str)

        self.status_message = "Finalizing scan results..."
        self.progress = 95

    def _run_nmap_scan(self, port_range_str):
        """Run port scan using nmap."""
        self.status_message = "Initializing nmap scan..."
        self.progress = 10
        self.scan_method = "nmap"

        # Calculate total ports to scan for progress tracking
        self.total_ports_to_scan = self._count_ports_in_range(port_range_str)
        self.ports_scanned = 0

        try:
            # Import nmap library
            import nmap

            # Initialize nmap scanner
            nm = nmap.PortScanner()

            # Determine scan arguments based on scan type
            if self.custom_nmap_args and self.scan_type == 'custom':
                # Use custom nmap arguments provided by the user
                args = self.custom_nmap_args
                logger.info(f"Using custom nmap arguments: {args}")
            elif self.scan_type == 'quick':
                # Quick scan with version detection
                args = '-sV --version-intensity 2 -T4'
            elif self.scan_type == 'standard':
                # Standard scan with version detection and OS detection
                args = '-sV -O --version-intensity 5 -T4'
            else:  # comprehensive
                # Comprehensive scan with all features
                args = '-sV -O -A --version-all --version-intensity 9 -T4 --script="banner,version,discovery"'

            self.status_message = f"Running nmap scan with arguments: {args}"
            self.progress = 15

            # Run the scan
            logger.info(f"Starting nmap scan of {self.target.ip_address} with port range {port_range_str}")

            # Update progress before scan
            self.status_message = f"Scanning {self.target.ip_address}..."
            self.progress = 25

            # Update state manager with progress
            from . import state_manager
            process_id = f"port_scan_{self.scan_result.id}"
            state_manager.update_process_data(process_id, {
                'progress': self.progress,
                'status_message': self.status_message,
                'total_ports': self.total_ports_to_scan,
                'ports_scanned': 0
            })

            # Start a thread to monitor nmap progress by checking the output file
            import tempfile
            import os
            import time

            # Create a temporary file for nmap output
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xml')
            output_file.close()

            # Add output file to args
            output_args = f"-oX {output_file.name}"
            full_args = f"{args} {output_args}"

            # Start progress monitoring thread
            def monitor_nmap_progress():
                import xml.etree.ElementTree as ET
                last_check_time = time.time()
                last_ports_scanned = 0

                while self.running:
                    try:
                        # Only check every 2 seconds to avoid excessive file reads
                        if time.time() - last_check_time < 2:
                            time.sleep(0.5)
                            continue

                        last_check_time = time.time()

                        # Check if file exists and has content
                        if os.path.exists(output_file.name) and os.path.getsize(output_file.name) > 0:
                            try:
                                tree = ET.parse(output_file.name)
                                root = tree.getroot()

                                # Get scan progress
                                hosts = root.findall(".//host")
                                if hosts:
                                    ports_scanned = 0
                                    for host in hosts:
                                        ports = host.findall(".//port")
                                        ports_scanned += len(ports)

                                    if ports_scanned > last_ports_scanned:
                                        last_ports_scanned = ports_scanned
                                        self.ports_scanned = ports_scanned

                                        # Calculate progress (25% at start, 75% at end)
                                        scan_progress = min(50, int(50 * ports_scanned / max(1, self.total_ports_to_scan)))
                                        self.progress = 25 + scan_progress
                                        self.status_message = f"Scanning {self.target.ip_address}: {ports_scanned} ports processed"

                                        # Update state manager
                                        state_manager.update_process_data(process_id, {
                                            'progress': self.progress,
                                            'status_message': self.status_message,
                                            'ports_scanned': ports_scanned,
                                            'total_ports': self.total_ports_to_scan
                                        })
                            except ET.ParseError:
                                # XML file might be incomplete while nmap is writing
                                pass
                    except Exception as e:
                        logger.error(f"Error monitoring nmap progress: {str(e)}")

                    time.sleep(0.5)

            # Start monitoring thread
            monitor_thread = threading.Thread(target=monitor_nmap_progress, daemon=True)
            monitor_thread.start()

            # Run the scan without callback (python-nmap doesn't support callbacks)
            nm.scan(self.target.ip_address, port_range_str, arguments=full_args)

            # Clean up the output file
            try:
                os.unlink(output_file.name)
            except:
                pass

            # Update progress after scan
            self.status_message = f"Scan completed for {self.target.ip_address}"
            self.progress = 75

            # Update state manager with progress
            state_manager.update_process_data(process_id, {
                'progress': self.progress,
                'status_message': self.status_message,
                'ports_scanned': self.ports_scanned,
                'total_ports': self.total_ports_to_scan
            })

            # Process results
            self.status_message = "Processing nmap scan results..."
            self.progress = 80

            # Check if target was scanned
            if self.target.ip_address in nm.all_hosts():
                host = nm[self.target.ip_address]

                # Get OS information if available
                os_info = ""
                if 'osmatch' in host and len(host['osmatch']) > 0:
                    os_match = host['osmatch'][0]
                    os_info = f"{os_match['name']} ({os_match['accuracy']}%)"

                    # Add OS info to scan result notes
                    self.scan_result.notes = f"OS Detection: {os_info}"
                    self.scan_result.save()

                # Process port information
                for proto in nm[self.target.ip_address].all_protocols():
                    ports = sorted(nm[self.target.ip_address][proto].keys())

                    for port in ports:
                        port_data = nm[self.target.ip_address][proto][port]

                        if port_data['state'] == 'open':
                            # Get service information
                            service_name = port_data.get('name', 'unknown')
                            service_version = port_data.get('product', '')

                            # Build detailed version string
                            version_parts = []
                            if 'product' in port_data and port_data['product']:
                                version_parts.append(port_data['product'])
                            if 'version' in port_data and port_data['version']:
                                version_parts.append(port_data['version'])
                            if 'extrainfo' in port_data and port_data['extrainfo']:
                                version_parts.append(f"({port_data['extrainfo']})")

                            service_version = " ".join(version_parts)

                            # Get banner information
                            banner = ""
                            if 'script' in port_data:
                                script_data = port_data['script']
                                if 'banner' in script_data:
                                    banner = script_data['banner']
                                elif 'fingerprint-strings' in script_data:
                                    banner = str(script_data['fingerprint-strings'])

                            # Store port information
                            self.open_ports[port] = {
                                'service': service_name,
                                'version': service_version,
                                'banner': banner or port_data.get('extrainfo', '')
                            }

                            # Save port info to database
                            PortInfo.objects.create(
                                scan_result=self.scan_result,
                                port_number=port,
                                service_name=service_name,
                                service_version=service_version,
                                banner=banner or port_data.get('extrainfo', ''),
                                protocol=proto,
                                is_open=True,
                                notes=str(port_data.get('script', ''))
                            )

            # Get scan summary
            scan_summary = nm.scaninfo()
            if scan_summary:
                # Add scan summary to notes
                current_notes = self.scan_result.notes or ""
                self.scan_result.notes = f"{current_notes}\nScan Summary: {scan_summary}"
                self.scan_result.save()

            logger.info(f"Nmap scan completed. Found {len(self.open_ports)} open ports.")

        except ImportError:
            logger.error("Python-nmap library not available. Falling back to custom scanner.")
            self.status_message = "Nmap library not available. Falling back to custom scanner."
            # Fall back to custom scanner
            self._run_custom_scan(port_range_str)

        except Exception as e:
            logger.error(f"Error during nmap scan: {str(e)}")
            self.status_message = f"Nmap scan failed: {str(e)}. Falling back to custom scanner."
            # Fall back to custom scanner
            self._run_custom_scan(port_range_str)

    def _run_custom_scan(self, port_range_str):
        """Run port scan using custom implementation."""
        self.status_message = "Starting custom port scan..."
        self.progress = 10
        self.scan_method = "builtin"

        # Calculate total ports to scan for progress tracking
        self.total_ports_to_scan = self._count_ports_in_range(port_range_str)
        self.ports_scanned = 0

        # Parse port range
        ports_to_scan = self._parse_port_range(port_range_str)
        total_ports = len(ports_to_scan)

        self.status_message = f"Scanning {total_ports} ports..."

        # Update state manager with initial progress
        from . import state_manager
        process_id = f"port_scan_{self.scan_result.id}"
        state_manager.update_process_data(process_id, {
            'progress': self.progress,
            'status_message': self.status_message,
            'ports_scanned': 0,
            'total_ports': total_ports
        })

        # Scan ports
        for i, port in enumerate(ports_to_scan):
            if not self.running:
                break

            # Update progress periodically
            if i % 20 == 0 or total_ports < 50:
                self.ports_scanned = i
                progress_pct = int((i / total_ports) * 70)
                self.progress = 15 + progress_pct
                self.status_message = f"Scanning port {port} ({i+1}/{total_ports})..."

                # Update state manager with progress
                state_manager.update_process_data(process_id, {
                    'progress': self.progress,
                    'status_message': self.status_message,
                    'ports_scanned': i + 1,
                    'total_ports': total_ports
                })

            # Check if port is open
            is_open = self._check_port(port)

            if is_open:
                # Detect service
                service_info = self._detect_service(port)

                # Store port information
                self.open_ports[port] = service_info

                # Save port info to database
                PortInfo.objects.create(
                    scan_result=self.scan_result,
                    port_number=port,
                    service_name=service_info.get('service', 'unknown'),
                    service_version=service_info.get('version', ''),
                    banner=service_info.get('banner', ''),
                    is_open=True
                )

    def _check_port(self, port):
        """Check if a port is open."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)  # Adjust timeout based on scan type
            result = s.connect_ex((self.target.ip_address, port))
            s.close()

            return result == 0
        except:
            return False

    def _detect_service(self, port):
        """Detect service running on an open port."""
        service_info = {
            'service': COMMON_PORTS.get(port, 'unknown'),
            'version': '',
            'banner': ''
        }

        try:
            # Try to get service banner
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.target.ip_address, port))

            # Send probe if available for the service
            service_name = service_info['service'].upper()
            if service_name in SERVICE_PROBES:
                probe = SERVICE_PROBES[service_name]
                if probe:
                    s.send(probe)

            # Receive banner
            banner = s.recv(1024)
            s.close()

            if banner:
                # Store banner
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner_str

                # Try to identify service from banner
                for service_name, pattern in SERVICE_FINGERPRINTS.items():
                    if re.search(pattern, banner):
                        service_info['service'] = service_name
                        break

                # Try to extract version information
                version_match = re.search(r'(\d+\.\d+(\.\d+)?)', banner_str)
                if version_match:
                    service_info['version'] = version_match.group(1)
        except:
            pass

        return service_info

    def get_status(self):
        """Get the current status of the port scan."""
        return {
            'running': self.running,
            'progress': self.progress,
            'status_message': self.status_message,
            'open_ports_count': len(self.open_ports),
            'scan_result_id': self.scan_result.id if self.scan_result else None,
            'scan_method': self.scan_method
        }

# Dictionary to store active scanners
active_port_scanners = {}

def get_port_scanner(target_id):
    """Get an active port scanner for a target."""
    return active_port_scanners.get(str(target_id))

def create_port_scanner(target, scan_type='standard', port_range=None, custom_nmap_args=None):
    """Create a new port scanner for a target."""
    scanner = PortScanner(target, scan_type, port_range, custom_nmap_args)
    active_port_scanners[str(target.id)] = scanner
    return scanner

def remove_port_scanner(target_id):
    """Remove a port scanner from the active scanners list."""
    if str(target_id) in active_port_scanners:
        del active_port_scanners[str(target_id)]
