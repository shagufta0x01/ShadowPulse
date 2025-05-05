from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import socket
import ipaddress
import subprocess
import re

def get_local_ip():
    """Get the local IP address of the host"""
    try:
        # Create a socket connection to an external server to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback to localhost if unable to determine
        return "127.0.0.1"

def get_subnet_from_ip(ip):
    """Get the subnet from an IP address (assumes /24 subnet)"""
    ip_parts = ip.split('.')
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

def arp_scan(network=None, timeout=3, verbose=False):
    """
    Perform an ARP scan on the local network
    
    Args:
        network (str): Network to scan (e.g. "192.168.1.0/24")
        timeout (int): Timeout for ARP requests
        verbose (bool): Whether to print verbose output
        
    Returns:
        list: List of dictionaries containing IP, MAC, and vendor information
    """
    if network is None:
        local_ip = get_local_ip()
        network = get_subnet_from_ip(local_ip)
    
    if verbose:
        print(f"Scanning network: {network}")
    
    # Create ARP request packets for all hosts in the network
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    # Send packets and receive responses
    answered, _ = srp(arp_request_broadcast, timeout=timeout, verbose=verbose)
    
    # Process the responses
    devices = []
    for sent, received in answered:
        mac = received.hwsrc
        ip = received.psrc
        
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = "Unknown"
        except Exception:
            vendor = "Error"
        
        devices.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor
        })
    
    return devices

def get_network_interfaces():
    """Get a list of network interfaces"""
    try:
        # Use ipconfig to get network interfaces on Windows
        output = subprocess.check_output(["ipconfig", "/all"], text=True)
        
        interfaces = []
        current_if = None
        
        for line in output.splitlines():
            if "adapter" in line and ":" in line:
                # New interface found
                if current_if:
                    interfaces.append(current_if)
                
                name = line.split(":")[0].strip()
                current_if = {
                    'name': name,
                    'ip': None,
                    'mac': None,
                    'subnet_mask': None
                }
            
            elif current_if:
                # Look for IP address
                if "IPv4 Address" in line and ":" in line:
                    ip = line.split(":")[-1].strip()
                    # Remove (Preferred) suffix if present
                    ip = ip.split("(")[0].strip()
                    current_if['ip'] = ip
                
                # Look for MAC address
                elif "Physical Address" in line and ":" in line:
                    mac = line.split(":")[-1].strip()
                    current_if['mac'] = mac
                
                # Look for subnet mask
                elif "Subnet Mask" in line and ":" in line:
                    mask = line.split(":")[-1].strip()
                    current_if['subnet_mask'] = mask
        
        # Add the last interface
        if current_if:
            interfaces.append(current_if)
        
        # Filter out interfaces without IP addresses
        return [iface for iface in interfaces if iface['ip']]
    
    except Exception as e:
        print(f"Error getting network interfaces: {str(e)}")
        return []

def get_default_gateway():
    """Get the default gateway IP address"""
    try:
        # Use ipconfig to get the default gateway
        output = subprocess.check_output(["ipconfig"], text=True)
        
        for line in output.splitlines():
            if "Default Gateway" in line and ":" in line:
                gateway = line.split(":")[-1].strip()
                if gateway and gateway != "":
                    return gateway
        
        return None
    except Exception:
        return None

def ping_host(ip, timeout=1):
    """Check if a host is reachable via ping"""
    try:
        output = subprocess.check_output(
            ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
            stderr=subprocess.STDOUT,
            text=True
        )
        return "TTL=" in output
    except subprocess.CalledProcessError:
        return False

def format_devices_table(devices):
    """Format a list of devices as a table string"""
    if not devices:
        return "No devices found"
    
    table = "Network Device Discovery:\n"
    table += "-" * 70 + "\n"
    table += f"{'IP Address':<20} {'MAC Address':<20} {'Vendor'}\n"
    table += "-" * 70 + "\n"
    
    for device in devices:
        table += f"{device['ip']:<20} {device['mac']:<20} {device['vendor']}\n"
    
    return table

if __name__ == "__main__":
    # Test the ARP scanner
    print("Scanning local network...")
    devices = arp_scan(verbose=True)
    print(format_devices_table(devices))
