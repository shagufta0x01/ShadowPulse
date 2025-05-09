"""
Network Monitoring System for Rex Security Scanner

This module provides real-time network traffic monitoring capabilities
that run on the host machine to analyze network traffic patterns,
detect anomalies, and provide security insights.
"""

import threading
import time
import socket
import struct
import datetime
import ipaddress
import logging
import json
import os
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS, Raw
from django.conf import settings
from django.utils import timezone
from .models import NetworkMonitorLog, NetworkTrafficStats, NetworkAlert

# Configure logging
logger = logging.getLogger(__name__)

class NetworkMonitor:
    """
    Network traffic monitoring system that captures and analyzes
    network packets to detect security issues and anomalies.
    """

    def __init__(self, interface=None, max_packets=10000, alert_threshold=0.8):
        """
        Initialize the network monitor.

        Args:
            interface (str): Network interface to monitor (None for auto-detect)
            max_packets (int): Maximum number of packets to keep in memory
            alert_threshold (float): Threshold for triggering alerts (0.0-1.0)
        """
        self.interface = interface
        self.max_packets = max_packets
        self.alert_threshold = alert_threshold
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None

        # Data structures for packet analysis
        self.recent_packets = deque(maxlen=max_packets)
        self.ip_connections = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.dns_queries = defaultdict(int)
        self.http_hosts = defaultdict(int)
        self.packet_sizes = []
        self.alerts = []

        # Statistics
        self.stats = {
            'start_time': None,
            'packets_captured': 0,
            'bytes_captured': 0,
            'last_update': None
        }

        # Known malicious patterns
        self.load_threat_intelligence()

    def load_threat_intelligence(self):
        """Load known malicious IP addresses, domains, and patterns from threat intelligence sources."""
        # Default empty sets
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.suspicious_ports = {22, 23, 445, 1433, 3389, 4444, 5900}  # Common attack targets

        # Path to threat intelligence files
        ti_path = os.path.join(settings.BASE_DIR, 'scanner', 'threat_intelligence')

        # Load malicious IPs if file exists
        ip_file = os.path.join(ti_path, 'malicious_ips.txt')
        if os.path.exists(ip_file):
            with open(ip_file, 'r') as f:
                self.malicious_ips = set(line.strip() for line in f if line.strip())

        # Load malicious domains if file exists
        domain_file = os.path.join(ti_path, 'malicious_domains.txt')
        if os.path.exists(domain_file):
            with open(domain_file, 'r') as f:
                self.malicious_domains = set(line.strip() for line in f if line.strip())

    def start_monitoring(self):
        """Start the network monitoring process."""
        if self.running:
            return False

        self.running = True
        self.stats['start_time'] = timezone.now()
        self.stats['last_update'] = timezone.now()

        # Register with state manager
        from . import state_manager
        process_id = f"network_monitor_{self.stats['start_time'].isoformat()}"
        state_manager.register_process(process_id, 'network_monitor', {
            'interface': self.interface or 'auto',
            'start_time': self.stats['start_time'].isoformat()
        })

        # Store process ID for later use
        self.process_id = process_id

        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analyze_traffic)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()

        # Register threads with state manager
        state_manager.register_thread(process_id, self.capture_thread)

        # Log the start of monitoring
        NetworkMonitorLog.objects.create(
            event_type='monitor_start',
            description=f'Network monitoring started on interface {self.interface or "auto"}'
        )

        return True

    def stop_monitoring(self):
        """Stop the network monitoring process."""
        if not self.running:
            return False

        self.running = False

        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)

        if self.analysis_thread:
            self.analysis_thread.join(timeout=2.0)

        # Unregister from state manager
        if hasattr(self, 'process_id'):
            from . import state_manager
            state_manager.unregister_process(self.process_id)

        # Log the stop of monitoring
        NetworkMonitorLog.objects.create(
            event_type='monitor_stop',
            description=f'Network monitoring stopped after capturing {self.stats["packets_captured"]} packets'
        )

        return True

    def _capture_packets(self):
        """Capture network packets using scapy."""
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            NetworkMonitorLog.objects.create(
                event_type='error',
                description=f'Packet capture error: {str(e)}'
            )

    def _process_packet(self, packet):
        """Process a captured packet."""
        # Update basic stats
        self.stats['packets_captured'] += 1

        # Extract packet size
        packet_size = len(packet)
        self.stats['bytes_captured'] += packet_size
        self.packet_sizes.append(packet_size)

        # Store packet for later analysis
        self.recent_packets.append(packet)

        # Analyze packet based on protocol
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Record IP connection
            self.ip_connections[(src_ip, dst_ip)] += 1

            # Check for known malicious IPs
            if src_ip in self.malicious_ips or dst_ip in self.malicious_ips:
                self._create_alert(
                    'malicious_ip',
                    f'Traffic detected involving known malicious IP: {src_ip if src_ip in self.malicious_ips else dst_ip}',
                    packet
                )

            # Process based on transport protocol
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                self.protocol_counts['TCP'] += 1
                self.port_activity[('TCP', dport)] += 1

                # Check for suspicious ports
                if dport in self.suspicious_ports:
                    self._create_alert(
                        'suspicious_port',
                        f'Connection to suspicious port {dport}/TCP from {src_ip}',
                        packet
                    )

                # Check for HTTP traffic
                if dport == 80 or sport == 80:
                    if Raw in packet:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload.startswith('GET ') or payload.startswith('POST '):
                            # Extract host from HTTP header
                            host_match = re.search(r'Host: ([^\r\n]+)', payload)
                            if host_match:
                                host = host_match.group(1).strip()
                                self.http_hosts[host] += 1

                                # Check for malicious domains
                                if host in self.malicious_domains:
                                    self._create_alert(
                                        'malicious_domain',
                                        f'HTTP request to known malicious domain: {host}',
                                        packet
                                    )

            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                self.protocol_counts['UDP'] += 1
                self.port_activity[('UDP', dport)] += 1

                # Process DNS queries
                if DNS in packet and packet.qr == 0:  # DNS query
                    query = packet[DNS].qd.qname.decode('utf-8')
                    self.dns_queries[query] += 1

                    # Check for malicious domains in DNS queries
                    for domain in self.malicious_domains:
                        if domain in query:
                            self._create_alert(
                                'malicious_dns',
                                f'DNS query for known malicious domain: {query}',
                                packet
                            )

            elif ICMP in packet:
                self.protocol_counts['ICMP'] += 1

                # Check for ICMP flood
                icmp_count = sum(1 for p in self.recent_packets if ICMP in p)
                if icmp_count > 100:  # Threshold for ICMP flood
                    self._create_alert(
                        'icmp_flood',
                        f'Possible ICMP flood detected: {icmp_count} ICMP packets in short period',
                        packet
                    )

        elif ARP in packet:
            self.protocol_counts['ARP'] += 1

            # Check for ARP spoofing
            if packet[ARP].op == 2:  # ARP reply
                # TODO: Implement ARP spoofing detection
                pass

    def _analyze_traffic(self):
        """Periodically analyze traffic patterns to detect anomalies."""
        while self.running:
            try:
                # Sleep for analysis interval
                time.sleep(10)

                # Skip analysis if not enough packets
                if len(self.recent_packets) < 100:
                    continue

                # Update traffic statistics in database
                self._update_traffic_stats()

                # Detect port scanning
                self._detect_port_scanning()

                # Detect unusual traffic patterns
                self._detect_unusual_traffic()

                # Detect data exfiltration
                self._detect_data_exfiltration()

            except Exception as e:
                logger.error(f"Error in traffic analysis: {str(e)}")
                NetworkMonitorLog.objects.create(
                    event_type='error',
                    description=f'Traffic analysis error: {str(e)}'
                )

    def _update_traffic_stats(self):
        """Update traffic statistics in the database."""
        now = timezone.now()
        duration = (now - self.stats['start_time']).total_seconds()

        if duration == 0:
            return

        # Calculate rates
        packets_per_second = self.stats['packets_captured'] / duration
        bytes_per_second = self.stats['bytes_captured'] / duration

        # Get protocol distribution
        total_packets = sum(self.protocol_counts.values())
        protocol_distribution = {
            proto: count / total_packets
            for proto, count in self.protocol_counts.items()
        }

        # Create or update traffic stats
        NetworkTrafficStats.objects.create(
            timestamp=now,
            packets_captured=self.stats['packets_captured'],
            bytes_captured=self.stats['bytes_captured'],
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            protocol_distribution=json.dumps(protocol_distribution),
            active_connections=len(self.ip_connections),
            unique_ips=len(set(ip for conn in self.ip_connections.keys() for ip in conn))
        )

        # Update last update time
        self.stats['last_update'] = now

        # Update state manager with current stats
        if hasattr(self, 'process_id'):
            from . import state_manager

            # Get top talkers (IPs with most traffic)
            ip_traffic = defaultdict(int)
            for (src, dst), count in self.ip_connections.items():
                ip_traffic[src] += count
                ip_traffic[dst] += count

            top_talkers = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]

            # Get top services (most active ports)
            top_services = sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:10]

            # Update state manager
            state_manager.update_process_data(self.process_id, {
                'packets_captured': self.stats['packets_captured'],
                'bytes_captured': self.stats['bytes_captured'],
                'packets_per_second': packets_per_second,
                'bytes_per_second': bytes_per_second,
                'protocol_distribution': protocol_distribution,
                'active_connections': len(self.ip_connections),
                'unique_ips': len(set(ip for conn in self.ip_connections.keys() for ip in conn)),
                'top_talkers': dict(top_talkers),
                'top_services': {f"{proto}:{port}": count for (proto, port), count in top_services},
                'recent_alerts': [alert['description'] for alert in self.alerts[-5:]] if self.alerts else [],
                'last_update': now.isoformat()
            })

    def _detect_port_scanning(self):
        """Detect potential port scanning activity."""
        # Group connections by source IP
        ip_port_counts = defaultdict(set)

        for packet in self.recent_packets:
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src

                if TCP in packet:
                    dst_port = packet[TCP].dport
                    ip_port_counts[src_ip].add(('TCP', dst_port))
                elif UDP in packet:
                    dst_port = packet[UDP].dport
                    ip_port_counts[src_ip].add(('UDP', dst_port))

        # Check for IPs connecting to many different ports
        for ip, ports in ip_port_counts.items():
            if len(ports) > 15:  # Threshold for port scanning
                self._create_alert(
                    'port_scan',
                    f'Possible port scan from {ip}: {len(ports)} ports in short period',
                    None
                )

    def _detect_unusual_traffic(self):
        """Detect unusual traffic patterns."""
        # Implement anomaly detection algorithms here
        pass

    def _detect_data_exfiltration(self):
        """Detect potential data exfiltration."""
        # Look for large outbound transfers
        outbound_data = defaultdict(int)

        for packet in self.recent_packets:
            if IP in packet:
                # Skip local traffic
                if packet[IP].dst.startswith('192.168.') or packet[IP].dst.startswith('10.'):
                    continue

                # Count outbound bytes by destination
                outbound_data[packet[IP].dst] += len(packet)

        # Alert on large transfers
        for dst_ip, bytes_sent in outbound_data.items():
            if bytes_sent > 1000000:  # 1MB threshold
                self._create_alert(
                    'data_exfiltration',
                    f'Large data transfer to external IP {dst_ip}: {bytes_sent/1000000:.2f} MB',
                    None
                )

    def _create_alert(self, alert_type, description, packet=None):
        """Create a security alert."""
        # Create alert object
        alert = {
            'type': alert_type,
            'description': description,
            'timestamp': timezone.now(),
            'packet_info': self._extract_packet_info(packet) if packet else None
        }

        # Add to alerts list
        self.alerts.append(alert)

        # Log to database
        alert_obj = NetworkAlert.objects.create(
            alert_type=alert_type,
            description=description,
            severity=self._determine_severity(alert_type),
            source_ip=alert['packet_info']['src_ip'] if alert['packet_info'] else None,
            destination_ip=alert['packet_info']['dst_ip'] if alert['packet_info'] else None,
            packet_info=json.dumps(alert['packet_info']) if alert['packet_info'] else None
        )

        # Update state manager with new alert
        if hasattr(self, 'process_id'):
            from . import state_manager

            # Get current alerts from state manager
            process_info = state_manager.get_process(self.process_id)
            if process_info:
                current_alerts = process_info.get('data', {}).get('alerts', [])

                # Add new alert
                new_alert = {
                    'id': alert_obj.id,
                    'type': alert_type,
                    'description': description,
                    'severity': self._determine_severity(alert_type),
                    'timestamp': alert['timestamp'].isoformat(),
                    'source_ip': alert['packet_info']['src_ip'] if alert['packet_info'] else None,
                    'destination_ip': alert['packet_info']['dst_ip'] if alert['packet_info'] else None
                }

                # Update state manager
                state_manager.update_process_data(self.process_id, {
                    'alerts': current_alerts + [new_alert],
                    'last_alert': new_alert
                })

        logger.warning(f"Network alert: {description}")

    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet for alerts."""
        info = {
            'timestamp': str(timezone.now()),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'size': len(packet)
        }

        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst

            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst

        return info

    def _determine_severity(self, alert_type):
        """Determine the severity level of an alert."""
        high_severity = ['malicious_ip', 'malicious_domain', 'data_exfiltration']
        medium_severity = ['port_scan', 'suspicious_port', 'malicious_dns']

        if alert_type in high_severity:
            return 'high'
        elif alert_type in medium_severity:
            return 'medium'
        else:
            return 'low'

    def get_statistics(self):
        """Get current monitoring statistics."""
        now = timezone.now()
        duration = (now - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0

        if duration == 0:
            return self.stats

        # Calculate rates
        packets_per_second = self.stats['packets_captured'] / duration
        bytes_per_second = self.stats['bytes_captured'] / duration

        # Get protocol distribution
        total_packets = sum(self.protocol_counts.values())
        protocol_distribution = {
            proto: count / total_packets
            for proto, count in self.protocol_counts.items()
        } if total_packets > 0 else {}

        # Get top talkers (IPs with most traffic)
        ip_traffic = defaultdict(int)
        for (src, dst), count in self.ip_connections.items():
            ip_traffic[src] += count
            ip_traffic[dst] += count

        top_talkers = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]

        # Get top services (most active ports)
        top_services = sorted(self.port_activity.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            **self.stats,
            'duration': duration,
            'packets_per_second': packets_per_second,
            'bytes_per_second': bytes_per_second,
            'protocol_distribution': protocol_distribution,
            'top_talkers': top_talkers,
            'top_services': top_services,
            'recent_alerts': self.alerts[-10:] if self.alerts else []
        }

    def get_recent_alerts(self, limit=50):
        """Get recent security alerts."""
        return self.alerts[-limit:] if self.alerts else []


# Global monitor instance
network_monitor = None

def get_monitor():
    """Get or create the global network monitor instance."""
    global network_monitor
    if network_monitor is None:
        network_monitor = NetworkMonitor()
    return network_monitor
