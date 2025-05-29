# ShadowPulse Scanner - Complete Documentation

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
   - [Component Overview](#21-component-overview)
   - [Communication Protocol](#22-communication-protocol)
3. [Core Functionality](#3-core-functionality)
   - [Vulnerability Scanning](#31-vulnerability-scanning)
   - [Port Scanning](#32-port-scanning)
   - [Network Monitoring](#33-network-monitoring)
   - [System Information Collection](#34-system-information-collection)
4. [Database Architecture](#4-database-architecture)
5. [Web Interface](#5-web-interface)
6. [Installation and Deployment](#6-installation-and-deployment)
   - [Prerequisites](#61-prerequisites)
   - [Dashboard Installation](#62-dashboard-installation)
   - [Agent Deployment](#63-agent-deployment)
   - [Docker Deployment](#64-docker-deployment)
7. [Usage Guide](#7-usage-guide)
   - [Target Management](#71-target-management)
   - [Vulnerability Scanning](#72-vulnerability-scanning)
   - [Port Scanning](#73-port-scanning)
   - [Network Monitoring](#74-network-monitoring)
8. [Technical Details](#8-technical-details)
   - [File Structure](#81-file-structure)
   - [Command Dispatcher System](#82-command-dispatcher-system)
   - [Security Features](#83-security-features)
9. [Troubleshooting](#9-troubleshooting)
10. [Future Development](#10-future-development)
11. [Detailed Component Documentation](#11-detailed-component-documentation)
    - [OsInfo Class](#111-osinfo-class)
    - [NetworkInfo Class](#112-networkinfo-class)
    - [Vulnerability Scanning](#113-vulnerability-scanning)
    - [Port Scanning](#114-port-scanning)
    - [Network Monitoring](#115-network-monitoring)
    - [ZAMBOT Protocol](#116-zambot-protocol)
12. [Project Structure and Files](#12-project-structure-and-files)
    - [Template Structure](#121-template-structure)
    - [Static Files](#122-static-files)
    - [Other Important Files](#123-other-important-files)
13. [Market Comparison and Advantages](#13-market-comparison-and-advantages)
    - [Competitive Analysis](#131-competitive-analysis)
    - [Key Differentiators](#132-key-differentiators)
    - [Target Market](#133-target-market)
14. [Contributing](#14-contributing)

## 1. Project Overview

### Introduction

ShadowPulse Scanner is an advanced security assessment and vulnerability management platform designed to provide comprehensive security analysis for networked systems. In today's increasingly complex cybersecurity landscape, organizations need robust tools to identify vulnerabilities, monitor network activity, and maintain security posture across their infrastructure.

### Problem Statement

Modern networks face numerous security challenges:
- Increasing sophistication of cyber attacks
- Growing number of connected devices and services
- Difficulty in maintaining visibility across complex networks
- Need for comprehensive security assessment tools
- Challenge of identifying vulnerabilities before they can be exploited
- Complexity in correlating security findings across different systems
- Challenges in prioritizing security issues based on risk
- Need for efficient and automated security assessment processes
- Difficulty in maintaining up-to-date security information
- Resource constraints for security monitoring and assessment

ShadowPulse Scanner addresses these challenges by providing a unified platform for security assessment, vulnerability management, and network monitoring.

### Application Architecture

The platform implements a client-server architecture with three main components:

1. **Dashboard**: A web-based interface for managing security operations
   - Provides visualization of security data
   - Enables configuration of scans and monitoring
   - Displays results and generates reports

2. **Host Controller**: Manages communication between the dashboard and agents
   - Coordinates scanning activities
   - Processes and aggregates data from agents
   - Implements the ZAMBOT protocol for secure communication

3. **Agent**: Runs on target systems to collect security information
   - Performs local scanning operations
   - Collects system and network information
   - Executes commands from the host controller

The system is designed to detect vulnerabilities, monitor network traffic, scan ports, and provide detailed system information to help identify and mitigate security risks.

## 2. System Architecture

### 2.1 Component Overview

#### Dashboard Component
- **Web-Based Interface**: Modern Django-based web application
- **Real-Time Visualization**: Interactive charts and graphs for security metrics
- **User Management**: Role-based access control with multi-user support
- **Notification System**: Alerts for critical security events
- **Report Generation Engine**: Flexible reporting capabilities

#### Controller Component
- **Command & Control Center**: Centralized management of security operations
- **Target Management**: Inventory and organization of target systems
- **Scan Orchestration**: Coordination of scanning activities across multiple targets
- **Data Processing Pipeline**: Processing and analysis of security data
- **Result Aggregation**: Consolidation of findings from multiple sources

#### Agent Component
- **Lightweight Client**: Efficient agent that runs on target systems
- **TCP Server (Port 23033)**: Communication endpoint for controller interaction
- **Modular Assessment Engine**: Pluggable security assessment modules
- **System Monitoring**: Real-time monitoring of system changes
- **Data Collection**: Efficient gathering of system and security information

### 2.2 Communication Protocol

ShadowPulse implements a custom binary protocol called ZAMBOT for agent-dashboard communication:

1. **Header Structure (19 bytes total)**:
   - Magic Header (6 bytes): 'ZAMBOT'
   - Version (1 byte): Protocol version number
   - Flags (1 byte): Control flags
   - Request ID (4 bytes): Unique request identifier
   - Command Code (1 byte): Operation code
   - Payload Length (4 bytes): Size of the payload
   - Reserved (2 bytes): Future use

2. **Command Codes**:
   - Basic commands (0x01-0x0F): OS_INFO, LIST_PRODUCTS, etc.
   - OS Info commands (0x10-0x2F): GET_OS_INFO, GET_AMSI_PROVIDERS, etc.
   - Network Info commands (0x30-0x4F): ARP_SCAN, DNS_CACHE, etc.
   - Vulnerability Scanning (0x50-0x5F): VULNERABILITY_SCAN, etc.

3. **Data Handling**:
   - Large responses are chunked (4KB chunks)
   - Compression for large payloads
   - Progress tracking for long operations
   - Timeout handling (30 seconds default)

## 3. Core Functionality

### 3.1 Vulnerability Scanning

The vulnerability scanning functionality allows for comprehensive security assessment of target systems:

- **Scan Types**:
  - Quick Scan: Basic security checks on common ports
  - Standard Scan: Comprehensive scan of common vulnerabilities
  - Deep Scan: Thorough analysis of all system components

- **Detection Capabilities**:
  - Service vulnerabilities
  - OS vulnerabilities
  - Configuration issues
  - Network security problems
  - Software vulnerabilities

- **Implementation**:
  - Agent-based scanning for accurate results
  - Local fallback scanning when agent is unavailable
  - CVE database integration for vulnerability identification
  - Severity classification (Critical, High, Medium, Low)

### 3.2 Port Scanning

The port scanning functionality provides detailed information about open ports and running services:

- **Scan Types**:
  - Quick Scan: Common ports only (21-23,25,53,80,443,3389,8080)
  - Standard Scan: Well-known ports (1-1024)
  - Comprehensive Scan: All ports (1-65535)
  - Custom Scan: User-defined port ranges

- **Detection Capabilities**:
  - Open port identification
  - Service detection
  - Version identification
  - Banner grabbing

- **Implementation**:
  - Primary Nmap-based scanning with service detection
  - Custom socket-based fallback scanner
  - Agent-based scanning for internal network access
  - Detailed results with service categorization

### 3.3 Network Monitoring

The network monitoring functionality provides real-time analysis of network traffic:

- **Monitoring Capabilities**:
  - Packet capture and analysis
  - Protocol distribution tracking
  - Connection monitoring
  - Bandwidth usage analysis
  - Anomaly detection

- **Security Features**:
  - Port scan detection
  - Malicious IP/domain detection
  - Data exfiltration detection
  - Unusual traffic pattern identification

- **Implementation**:
  - Scapy-based packet capture
  - Real-time traffic analysis
  - Statistical anomaly detection
  - Alert generation for security issues

### 3.4 System Information Collection

The system information collection functionality provides detailed information about target systems:

- **Information Categories**:
  - Basic OS information
  - Installed software
  - Running processes
  - Network configuration
  - Security settings
  - User accounts
  - System configuration

- **Implementation**:
  - PowerShell-based collection on Windows
  - Shell command execution for data gathering
  - Structured data formatting for analysis
  - Section-based information organization

## 4. Database Architecture

ShadowPulse uses SQLite (db.sqlite3) as its database engine, implementing a comprehensive schema for security scanning and monitoring:

### 4.1 Core Models

- **Target**: Systems under security assessment
- **ScanResult**: Results from completed scans
- **Vulnerability**: Identified security issues
- **NetworkDevice**: Discovered network devices
- **NetworkAlert**: Security alerts from monitoring

### 4.2 Database Operations

The project includes several key functions for saving data to the database:

#### Network Device Discovery
- **File**: `dashboard/scanner/views.py`
- **Function**: `scan_network()`
- **Purpose**: Scans the network and saves discovered devices using `NetworkDevice.objects.update_or_create()`

#### Vulnerability Management
- **File**: `dashboard/scanner/vulnerability_scanner.py`
- **Function**: `_add_vulnerability()`
- **Purpose**: Creates vulnerability records in the database using `Vulnerability.objects.create()`

#### Software Inventory Management
- **File**: `dashboard/scanner/software_vulnerability_scanner.py`
- **Function**: `get_installed_software()`
- **Purpose**: Extracts and saves software inventory using `InstalledSoftware.objects.update_or_create()`

#### Port Scan Results
- **File**: `dashboard/scanner/views_port_scanner.py`
- **Function**: `start_port_scan()`
- **Purpose**: Creates port scan records and saves results using `PortScanResult.objects.create()`

#### Network Monitoring
- **File**: `dashboard/scanner/network_monitor.py`
- **Function**: `_create_alert()`
- **Purpose**: Creates network security alerts using `NetworkAlert.objects.create()`

#### Client-Side Data Persistence
- **File**: `dashboard/static/js/data-persistence.js`
- **Functions**: `DataPersistence.saveData()`, `OsInfoData.saveInfo()`, `NetworkDevicesData.saveDevices()`
- **Purpose**: Provides client-side data persistence using browser's localStorage

### 4.3 Port Scanning Models

- **PortScanResult**: Results of port scanning operations
- **PortInfo**: Detailed information about individual ports

### 4.4 Vulnerability Models

- **SoftwareVulnerabilityScan**: Software vulnerability scan results
- **SoftwareVulnerability**: Identified software vulnerabilities
- **InstalledSoftware**: Software inventory from target systems

### 4.5 Network Monitoring Models

- **NetworkMonitorLog**: Logging of monitoring events
- **NetworkTrafficStats**: Network traffic statistics
- **NetworkAlert**: Security alerts from monitoring

## 5. Web Interface

The web interface provides a user-friendly way to interact with the system:

### 5.1 Main Sections

- **Dashboard**: Overview of system security status
- **Target Management**: Add and manage target systems
- **Vulnerability Management**: View and manage vulnerabilities
- **Port Scanner**: Scan and view open ports
- **Network Monitor**: Real-time network traffic analysis
- **System Information**: Detailed target system information

### 5.2 Key Features

- **Real-time Updates**: Live updates of scan progress and results
- **Data Visualization**: Charts and graphs for security metrics
- **Report Generation**: Generate comprehensive security reports
- **Alert Management**: View and manage security alerts
- **User Authentication**: Secure access control

## 6. Installation and Deployment

### 6.1 Prerequisites

- Python 3.8 or higher
- Django 4.2
- Network access to target systems
- Administrative privileges on target systems (for agent installation)
- Required Python packages (see requirements.txt)

### 6.2 Dashboard Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/vuln_scanner.git
   cd vuln_scanner
   ```

2. **Set Up Environment**:
   ```bash
   # Create a virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install dependencies
   cd dashboard
   pip install -r requirements.txt
   ```

3. **Configure Settings**:
   - Copy `.env.example` to `.env`
   - Modify settings as needed

4. **Initialize Database**:
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

5. **Run Development Server**:
   ```bash
   python manage.py runserver
   ```

### 6.3 Agent Deployment

1. **Build Agent Executable**:
   ```bash
   # On Windows
   build_agent.bat

   # Or using Python directly
   python build_agent_exe.py
   ```

2. **Deploy Agent to Target Systems**:
   - Copy `agent_listener.exe` to target system
   - Run the executable with administrative privileges

3. **Agent Configuration**:
   - By default, the agent listens on port 23033
   - No additional configuration is required

### 6.4 Docker Deployment

1. **Using Docker Compose**:
   ```bash
   # Development environment
   docker-compose up

   # Production environment
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

2. **Docker Deployment Features**:
   - Automatic database initialization and migration
   - Health checks for all services
   - Resource limits for production deployment
   - Nginx configuration for static files and proxying
   - Separate development and production configurations
   - SSL support (requires certificates)

3. **Accessing the Application**:
   - Development: http://localhost:8000/ (direct Django access)
   - Production: http://localhost/ (through Nginx)
   - Admin interface: http://localhost/admin/

## 7. Usage Guide

### 7.1 Target Management

1. **Adding Targets**:
   - Navigate to Target Management
   - Click "Add Target"
   - Enter IP address and hostname
   - Click "Save"

2. **Managing Targets**:
   - View all targets on the Target Management page
   - Click on a target to view details
   - Use the "Delete" button to remove targets

3. **Target Details**:
   - View all scan results for a target
   - Initiate new scans
   - View system information

### 7.2 Vulnerability Scanning

1. **Starting a Scan**:
   - Select a target
   - Choose scan type (Quick, Standard, Deep)
   - Click "Start Scan"

2. **Viewing Results**:
   - Navigate to Vulnerability Management
   - Select a scan to view details
   - View vulnerabilities by severity

3. **Managing Vulnerabilities**:
   - Mark vulnerabilities as "In Progress" or "Resolved"
   - Add notes to vulnerabilities
   - Filter vulnerabilities by severity or status

### 7.3 Port Scanning

1. **Starting a Port Scan**:
   - Navigate to Port Scanner
   - Select a target
   - Choose scan type or custom port range
   - Click "Start Scan"

2. **Viewing Results**:
   - View open ports and services
   - Filter by service type
   - View detailed port information

3. **Advanced Options**:
   - Use custom Nmap arguments for advanced scanning
   - Export results to CSV
   - Schedule regular scans

### 7.4 Network Monitoring

1. **Starting Monitoring**:
   - Navigate to Network Monitor
   - Select network interface (optional)
   - Click "Start Monitoring"

2. **Viewing Statistics**:
   - View real-time traffic statistics
   - Monitor protocol distribution
   - Track bandwidth usage

3. **Managing Alerts**:
   - View security alerts
   - Mark alerts as resolved
   - Configure alert thresholds

## 8. Technical Details

### 8.1 File Structure

```
vuln_scanner/
├── dashboard/              # Web dashboard (Django project)
│   ├── dashboard/          # Django project settings
│   │   ├── settings.py     # Development settings
│   │   ├── settings_prod.py # Production settings
│   │   ├── urls.py         # Main URL routing
│   │   ├── wsgi.py         # WSGI configuration
│   │   └── asgi.py         # ASGI configuration
│   ├── scanner/            # Main application
│   │   ├── templates/      # HTML templates
│   │   ├── static/         # Static assets (CSS, JS, images)
│   │   ├── models.py       # Database models
│   │   ├── views.py        # Main view controllers
│   │   ├── views_monitoring.py # Network monitoring views
│   │   ├── views_port_scanner.py # Port scanning views
│   │   ├── views_software_vuln_scanner.py # Vulnerability scanning views
│   │   ├── urls.py         # Application URL routing
│   │   ├── network_monitor.py # Network monitoring functionality
│   │   └── software_vulnerability_scanner.py # Vulnerability scanning logic
│   ├── manage.py           # Django management script
│   └── requirements.txt    # Python dependencies for dashboard
├── proto/                  # Protocol and agent implementation
│   ├── pro/                # Protocol definitions
│   │   └── protocol.py     # ZAMBOT protocol constants and structures
│   ├── host/               # Host/controller side implementation
│   │   ├── host_controller.py # Main controller implementation
│   │   ├── utils.py        # Utility functions for host
│   │   └── network_utils.py # Network utilities
│   ├── agent/              # Agent implementation
│   │   ├── agent_listener.py # Main agent listener implementation
│   │   ├── handlers.py     # Command handlers for agent
│   │   ├── http_handler.py # HTTP server implementation
│   │   ├── utils.py        # Utility functions for agent
│   │   └── vulnerability_scanner.py # Vulnerability scanning functionality
├── docs/                   # Documentation
├── scanner/                # Additional scanner functionality
│   └── vulnerability_db/   # Vulnerability database files
├── build_agent_exe.py      # Script to build agent executable
├── build_agent.bat         # Batch file to run build script on Windows
├── agent_listener.exe      # Compiled agent executable (after build)
└── docker-compose.yml      # Docker configuration for production
```

### 8.2 Command Dispatcher System

The command_dispatcher function in handlers.py acts as the central hub for processing commands:

```python
def command_dispatcher(cmd_code, **kwargs):
    # Initialize handlers
    os_info = OsInfo()
    net_info = NetworkInfo()

    # Route command to appropriate handler
    if cmd_code == CMD_OS_INFO:
        return os_info.handle_basic_info()
    elif cmd_code == CMD_NETWORK_SCAN:
        return net_info.arp_scan()
    # etc.
```

### 8.3 Security Features

1. **Memory Protection**:
   - Buffer overflow prevention
   - Memory sanitization
   - Secure data handling

2. **Network Security**:
   - Encrypted communication (optional)
   - Connection validation
   - Timeout handling

3. **Authentication**:
   - User authentication for web interface
   - Role-based access control
   - Password policy enforcement

## 9. Troubleshooting

### 9.1 Common Issues

1. **Agent Connection Failures**:
   - Verify agent is running on target system
   - Check firewall settings (port 23033 must be open)
   - Ensure correct IP address is configured

2. **Scan Failures**:
   - Check network connectivity
   - Verify agent has sufficient permissions
   - Check for antivirus interference

3. **Web Interface Issues**:
   - Clear browser cache
   - Check Django error logs
   - Verify database connectivity

### 9.2 Logging

1. **Dashboard Logs**:
   - Located in `dashboard/logs/django.log`
   - Contains web interface and scan errors

2. **Agent Logs**:
   - Printed to console by default
   - Can be redirected to a file

3. **Network Monitor Logs**:
   - Stored in the database (NetworkMonitorLog model)
   - Accessible through the web interface

## 10. Future Development

### 10.1 Planned Features

1. **Enhanced Reporting**:
   - PDF report generation
   - Scheduled report delivery
   - Compliance reporting templates

2. **Advanced Scanning**:
   - Web application vulnerability scanning
   - Wireless network security assessment
   - Container security scanning

3. **Integration Capabilities**:
   - API for third-party integration
   - SIEM integration
   - Ticketing system integration

### 10.2 Contributing

Contributions to ShadowPulse Scanner are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 11. Detailed Component Documentation

This section provides in-depth documentation for key components of the ShadowPulse Scanner system.

### 11.1 OsInfo Class

#### Introduction

The OsInfo class is a core component of the ShadowPulse Scanner's agent functionality. It provides comprehensive system information collection capabilities, including OS details, hardware information, and system configuration. This component is essential for security assessment as it provides the baseline information about the target system that is necessary for vulnerability analysis.

#### Application Used

The OsInfo class is used in the following scenarios:

- Initial system assessment during security audits
- Baseline configuration documentation
- System inventory management
- Vulnerability assessment prerequisites
- Security compliance verification

#### Source Functions

The OsInfo class is defined in `proto/agent/handlers.py` and includes the following key functions:

| Function | Purpose |
|----------|---------|
| `handle_basic_info()` | Retrieves basic system information |
| `get_os_info()` | Collects detailed OS information |
| `format_output()` | Formats data in both text and HTML formats |
| `_get_os_info_fallback()` | Provides fallback method for OS information collection |
| `_generate_error_html()` | Creates standardized error messages |

#### Key Methods

##### handle_basic_info()

**Purpose**: Gets basic system information and returns formatted HTML for web display

**Implementation Details**:
```python
def handle_basic_info(self):
    """Get basic system information and return formatted HTML for web display"""
    # We only need web display output
    command = """
    # Get basic system information efficiently
    $systemInfo = @{
        "System Overview" = @()
        "CPU Information" = @()
        "Memory Status" = @()
        "Disk Information" = @()
    }

    # System overview - use Environment class for better performance
    $systemInfo["System Overview"] += @{
        "Name" = "OS Name"
        "Value" = [System.Environment]::OSVersion.VersionString
    }
    # ...
    """
```

**Implementation Details**:
- Uses PowerShell commands to retrieve system information
- Collects data about OS, CPU, memory, and disk
- Formats data as HTML for web display
- Provides fallback mechanisms if PowerShell fails

**Key Features**:
- Comprehensive system information
- Efficient data collection
- Formatted HTML output
- Fallback mechanisms

##### get_os_info()

**Purpose**: Gets detailed OS information

**Implementation Details**:
```python
def get_os_info(self):
    if 'web_display' in self.__dict__ and self.web_display:
        command = """
        # Add System.Web for HTML encoding
        Add-Type -AssemblyName System.Web

        # Create a function to safely get WMI data
        function Get-SafeWmiData {
            param (
                [string]$Class,
                [string]$Property = "*"
            )
            # ...
        }

        # Get OS information from multiple sources
        $osInfo = @{
            "Basic Information" = @()
            "System Details" = @()
            "Hardware" = @()
            "Memory" = @()
            "Network" = @()
        }
        # ...
        """
```

**Implementation Details**:
- Uses WMI to retrieve detailed OS information
- Collects data from multiple sources
- Formats data as HTML for web display
- Provides fallback mechanisms

**Key Features**:
- Detailed OS information
- Hardware details
- Memory information
- Network configuration

##### format_output(title, data, headers=None, is_table=True)

**Purpose**: Formats output in both text and HTML formats

**Parameters**:
- **title**: The title of the output
- **data**: List of dictionaries or list of lists with the data
- **headers**: List of column headers (required for list of lists data)
- **is_table**: Whether to format as a table or key-value pairs

**Implementation Details**:
```python
def format_output(self, title, data, headers=None, is_table=True):
    """
    Format output in both text and HTML formats

    Args:
        title (str): The title of the output
        data (list): List of dictionaries or list of lists with the data
        headers (list, optional): List of column headers. Required for list of lists data.
        is_table (bool): Whether to format as a table or key-value pairs

    Returns:
        dict: Dictionary with 'text' and 'html' keys
    """
    # Create text output
    text_output = f"{title}:\n"
    text_output += "-" * 70 + "\n"

    # Create HTML output
    # ...
```

**Implementation Details**:
- Supports both table and key-value pair formats
- Handles different data structures (dictionaries, lists)
- Creates both text and HTML outputs
- Provides consistent formatting

**Key Features**:
- Dual-format output (text and HTML)
- Flexible data handling
- Consistent styling
- Error handling

#### Integration with Command Dispatcher

The OsInfo class is integrated with the command dispatcher system in the agent's handlers.py file:

```python
def command_dispatcher(cmd_code, **kwargs):
    # Initialize handlers
    os_info = OsInfo()
    net_info = NetworkInfo()

    # OS Info command codes
    if cmd_code == CMD_OS_INFO:
        return os_info.handle_basic_info()
    elif cmd_code == CMD_GET_OS_INFO:
        return os_info.get_os_info()
    # etc.
```

#### Output

The OsInfo class produces structured output in both text and HTML formats. The output is designed to be:
- Visually appealing and easy to read in the web interface
- Well-structured for programmatic parsing
- Comprehensive, covering all relevant system information
- Consistent across different target systems

**Screenshot to add**:
Add a screenshot of the System Information page from the dashboard showing multiple information cards including:
- System Overview card (showing OS name, computer name, system uptime)
- CPU Information card
- Memory Status card
- Disk Information card

*Note: The actual output includes multiple cards for different categories of system information, including CPU details, memory status, disk information, and network configuration.*

### 11.2 NetworkInfo Class

#### Introduction

The NetworkInfo class is a core component of the ShadowPulse Scanner's agent functionality. It provides comprehensive network reconnaissance and analysis capabilities, including device discovery, port scanning, and network service analysis. This component is crucial for understanding the network environment of target systems and identifying potential security issues related to network configuration and services.

#### Application Used

The NetworkInfo class is used in the following scenarios:

- Network device inventory and mapping
- Open port and service discovery
- Network share and connection analysis
- DNS configuration assessment
- Network profile evaluation
- Security posture assessment

#### Source Functions

The NetworkInfo class is defined in `proto/agent/handlers.py` and includes the following key functions:

| Function | Purpose |
|----------|---------|
| `arp_scan()` | Discovers active devices on the network |
| `port_scanner()` | Identifies open ports and services on target systems |
| `tcp_udp_connections()` | Lists active network connections |
| `network_shares()` | Enumerates available network shares |
| `dns_cache()` | Retrieves DNS cache information |
| `windows_network_profile()` | Gets network profile configuration |

#### Class Initialization

```python
def __init__(self, routerip="192.168.29.1", network="192.168.29.0/24", iface=None, web_display=False):
    self.routerip = routerip      # Default router IP
    self.network = network        # Target network range
    self.iface = iface if iface else conf.iface  # Network interface
    self.web_display = web_display  # Output format toggle
```

##### Parameters

- **routerip**: Default router IP address (default: "192.168.29.1")
- **network**: Target network range in CIDR notation (default: "192.168.29.0/24")
- **iface**: Network interface to use (default: auto-detect)
- **web_display**: Whether to format output for web display (default: False)

#### Key Methods

##### arp_scan()

**Purpose**: Performs ARP scanning to discover active devices on the network

**Implementation Details**:
```python
def arp_scan(self):
    # Perform ARP scan
    devices = []
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network), timeout=5, iface=self.iface, verbose=False)

    for _, received in ans:
        mac = received[ARP].hwsrc
        ip = received.psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = "Unknown"

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor
        })
```

- Uses Scapy for ARP request broadcasting
- Identifies active devices through responses
- Collects MAC addresses and attempts vendor lookup
- Provides both HTML and text-based output formats

**Key Features**:
- MAC address detection
- Vendor identification
- Response timeout handling (5 seconds)
- Formatted output (HTML/Text)

**Example Usage**:
```python
net_info = NetworkInfo(network="192.168.1.0/24")
devices = net_info.arp_scan()
```

##### port_scanner(ip_to_scan)

**Purpose**: Scans target systems for open ports and identifies running services

**Implementation Details**:
```python
def port_scanner(self, ip_to_scan):
    # Scan for open ports
    open_ports = []
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        115: "SFTP",
        135: "RPC",
        139: "NetBIOS",
        143: "IMAP",
        194: "IRC",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5632: "PCAnywhere",
        5900: "VNC",
        8080: "HTTP-Proxy"
    }
```

**Parameters**:
- **ip_to_scan**: IP address to scan (string)

**Implementation Details**:
- Uses socket connections to check port status
- Attempts service identification through banner grabbing
- Supports configurable port ranges and timeouts
- Provides formatted output for web display

**Key Features**:
- Open port detection
- Service identification
- Banner grabbing
- Configurable scan parameters

##### tcp_udp_connections()

**Purpose**: Lists active TCP and UDP connections on the system

**Implementation Details**:
```python
def tcp_udp_connections(self):
    # Use PowerShell to get network connections with HTML output
    command = """
    $connections = Get-NetTCPConnection |
    ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            ProcessId = $_.OwningProcess
            ProcessName = if ($process) { $process.Name } else { "Unknown" }
        }
    }
    """
```

**Implementation Details**:
- Uses system commands to retrieve connection information
- Parses and formats connection data
- Provides both HTML and text-based output formats

**Key Features**:
- TCP connection listing
- UDP connection listing
- Process association (when available)
- Connection state information

##### network_shares()

**Purpose**: Lists network shares available on the system

**Implementation Details**:
```python
def network_shares(self):
    table = "Network Shares:\n"
    table += "-" * 70 + "\n"
    try:
        shares = subprocess.check_output(["powershell", "Get-SmbShare | Format-Table -AutoSize"], text=True)
        table += shares
```

**Implementation Details**:
- Uses system commands to retrieve share information
- Parses and formats share data
- Provides both HTML and text-based output formats

**Key Features**:
- Share name listing
- Share path information
- Share permissions (when available)
- Share type identification

##### dns_cache()

**Purpose**: Retrieves the DNS cache from the system

**Implementation Details**:
```python
def dns_cache(self):
    try:
        output = subprocess.check_output(["ipconfig", "/displaydns"], text=True)
        return output.encode()
    except subprocess.CalledProcessError as e:
        return f"Error retrieving DNS cache: {str(e)}".encode()
```

**Implementation Details**:
- Uses ipconfig command to retrieve DNS cache information
- Returns raw output or error message
- Provides both HTML and text-based output formats

**Key Features**:
- DNS record listing
- Complete cache information
- Error handling

##### windows_network_profile()

**Purpose**: Retrieves Windows network profile information

**Implementation Details**:
```python
def windows_network_profile(self):
    table = "Network Configuration:\n"
    table += "=" * 70 + "\n\n"

    try:
        # Network Adapters
```

**Implementation Details**:
- Uses PowerShell commands to retrieve network profile information
- Parses and formats profile data
- Provides both HTML and text-based output formats

**Key Features**:
- Network profile name
- Connection type
- Network category
- Authentication settings

#### Integration with Command Dispatcher

The NetworkInfo class is integrated with the command dispatcher system in the agent's handlers.py file:

```python
def command_dispatcher(cmd_code, **kwargs):
    # Initialize NetworkInfo with custom network parameters if provided
    ip_to_scan = kwargs.get("ip", "192.168.29.1")
    network = kwargs.get("network", "192.168.29.0/24")
    net_info = NetworkInfo(routerip=ip_to_scan, network=network, web_display=True)

    # Network Info command codes
    if cmd_code == CMD_ARP_SCAN:
        return net_info.arp_scan()
    elif cmd_code == CMD_DNS_CACHE:
        return net_info.dns_cache()
    elif cmd_code == CMD_WINDOWS_NETWORK_PROFILE:
        return net_info.windows_network_profile()
    elif cmd_code == CMD_NETWORK_SHARES:
        return net_info.network_shares()
    elif cmd_code == CMD_TCP_UDP_CONNECTIONS:
        return net_info.tcp_udp_connections()
    elif cmd_code == CMD_PORT_SCANNER:
        return net_info.port_scanner(ip_to_scan)
    # etc.
```

#### Dependencies

- **Scapy**: Used for ARP scanning and packet manipulation
- **mac_vendor_lookup**: Used for MAC address vendor identification
- **socket**: Used for port scanning
- **subprocess**: Used for executing system commands
- **re**: Used for parsing command output

#### Output

The NetworkInfo class produces structured output in both text and HTML formats. The output is designed to be:
- Visually organized by function (ARP scan, port scan, etc.)
- Tabular for easy data interpretation
- Comprehensive, showing all relevant network information
- Consistent across different target systems

**Screenshots to add**:
1. **ARP Scan Results**: Add a screenshot showing the Network Devices table with columns for IP Address, MAC Address, and Vendor
2. **Port Scanner Results**: Add a screenshot showing the Open Ports table with columns for Port, Service, and Banner
3. **Network Connections**: Add a screenshot showing the TCP/UDP Connections table
4. **Network Shares**: Add a screenshot showing the Network Shares information

*Note: The actual output will vary based on the network environment and the specific function being called.*

### 11.3 Vulnerability Scanning

#### Introduction

The vulnerability scanning functionality in ShadowPulse Scanner provides comprehensive security assessment capabilities for target systems. It can detect various types of vulnerabilities, including service vulnerabilities, OS vulnerabilities, configuration issues, and software vulnerabilities. This component is essential for identifying security weaknesses that could be exploited by attackers.

#### Application Used

The vulnerability scanning functionality is used in the following scenarios:

- Regular security assessments
- Compliance verification (PCI DSS, HIPAA, etc.)
- Post-patch verification
- Pre-deployment security testing
- Incident response and forensics
- Security posture monitoring

#### Source Functions

The vulnerability scanning functionality is implemented across multiple files:

| File | Key Functions |
|------|---------------|
| `proto/agent/vulnerability_scanner.py` | `start_scan()`, `_quick_scan()`, `_standard_scan()`, `_deep_scan()`, `_check_service_vulnerabilities()`, `_check_os_vulnerabilities()` |
| `dashboard/scanner/software_vulnerability_scanner.py` | `start_scan()`, `_get_installed_software()`, `_check_software_vulnerabilities()` |
| `dashboard/scanner/views_software_vuln_scanner.py` | `software_vuln_scan_home()`, `start_software_vuln_scan()`, `software_vuln_scan_results()` |
| `dashboard/scanner/models.py` | Database models for storing scan results and vulnerabilities |

#### Vulnerability Scanner Class (Agent-Side)

##### Location

`proto/agent/vulnerability_scanner.py`

##### Class Initialization

```python
def __init__(self, scan_type="standard"):
    """
    Initialize the vulnerability scanner.

    Args:
        scan_type (str): Type of scan to perform (quick, standard, deep)
    """
    self.scan_type = scan_type
    self.vulnerabilities = []
    self.scan_start_time = None
    self.scan_end_time = None
    self.os_info = self._get_os_info()

    # Load vulnerability database
    self._load_vulnerability_database()
```

##### Key Methods

###### start_scan()

**Purpose**: Initiates the vulnerability scanning process

**Implementation Details**:
- Determines scan depth based on scan type
- Calls appropriate scan method (quick, standard, deep)
- Records scan timing information
- Formats and returns results

**Example Usage**:
```python
scanner = VulnerabilityScanner(scan_type="standard")
results = scanner.start_scan()
```

###### _quick_scan()

**Purpose**: Performs a quick vulnerability scan

**Implementation Details**:
- Checks for common configuration issues
- Checks for common service vulnerabilities on key ports
- Checks for OS vulnerabilities
- Faster but less comprehensive than other scan types

###### _standard_scan()

**Purpose**: Performs a standard vulnerability scan

**Implementation Details**:
- Runs quick scan checks
- Checks for additional service vulnerabilities on well-known ports
- Checks for network configuration issues
- Checks for web vulnerabilities if web server is running

###### _deep_scan()

**Purpose**: Performs a deep vulnerability scan

**Implementation Details**:
- Runs standard scan checks
- Checks for additional service vulnerabilities on high ports
- Checks for file system vulnerabilities
- Checks for registry vulnerabilities (Windows only)
- Most comprehensive but slowest scan type

#### Software Vulnerability Scanner Class (Dashboard-Side)

##### Location

`dashboard/scanner/software_vulnerability_scanner.py`

##### Class Initialization

```python
def __init__(self, target_id, scan_id=None):
    """Initialize the scanner with a target ID"""
    self.target_id = target_id
    self.scan_id = scan_id
    self.target = Target.objects.get(id=target_id)
    self.running = False
    self.progress = 0
    self.status_message = "Initializing..."
    self.vulnerabilities = []

    # API configuration
    self.nvd_api_key = None  # Optional: Add your NVD API key here
    self.vulners_api_key = None  # Optional: Add your Vulners API key here

    # Path to local vulnerability database
    self.vuln_db_path = os.path.join(settings.BASE_DIR, 'scanner', 'vulnerability_db')

    # Cache for vulnerability lookups
    self._vulnerability_cache = {}
```

##### Key Methods

###### start_scan(process_id=None)

**Purpose**: Initiates the software vulnerability scanning process

**Parameters**:
- **process_id**: Optional process ID for state management

**Implementation Details**:
- Registers the scan with the state manager
- Gets installed software list from target
- Checks each software for vulnerabilities
- Updates database with results
- Creates alerts for high severity vulnerabilities

###### _get_installed_software()

**Purpose**: Retrieves the list of installed software from the target

**Implementation Details**:
- Attempts to get software list from agent
- Falls back to extracting from OS info if agent communication fails
- Saves software to database
- Returns list of software objects

###### _check_software_vulnerabilities(software_list)

**Purpose**: Checks each software for known vulnerabilities

**Parameters**:
- **software_list**: List of software objects to check

**Implementation Details**:
- Iterates through each software item
- Checks local vulnerability database
- Optionally checks online vulnerability databases
- Creates vulnerability records for found issues

#### Output

The vulnerability scanning functionality produces detailed reports of identified vulnerabilities. The output is designed to be:
- Categorized by severity (Critical, High, Medium, Low)
- Detailed, providing CVE IDs, affected software, and descriptions
- Actionable, with links to vulnerability details and remediation options
- Visual, using color-coding to highlight severity levels

**Screenshots to add**:
1. **Vulnerability Scan Summary**: Add a screenshot showing the summary cards with counts of Critical, High, Medium, and Low vulnerabilities
2. **Critical Vulnerabilities List**: Add a screenshot showing the table of critical vulnerabilities with columns for CVE ID, Software, Version, CVSS Score, Description, and Actions
3. **Vulnerability Details**: Add a screenshot showing the detailed view of a specific vulnerability with remediation information

*Note: The actual output will vary based on the target system and the vulnerabilities found during the scan.*

### 11.4 Port Scanning

#### Introduction

The port scanning functionality in ShadowPulse Scanner provides comprehensive port discovery and service identification capabilities. It can detect open ports, identify running services, and gather detailed information about network services on target systems. This component is crucial for understanding the attack surface of target systems and identifying potentially vulnerable services.

#### Application Used

The port scanning functionality is used in the following scenarios:

- Network security assessments
- Attack surface analysis
- Service inventory management
- Compliance verification
- Unauthorized service detection
- Pre-deployment security testing

#### Source Functions

The port scanning functionality is implemented across multiple files:

| File | Key Functions |
|------|---------------|
| `dashboard/scanner/port_scanner.py` | `start_scan()`, `_run_scan()`, `_run_nmap_scan()`, `_run_custom_scan()`, `_get_port_range_str()`, `_parse_port_range()` |
| `proto/agent/handlers.py` | `port_scanner()` (in NetworkInfo class) |
| `dashboard/scanner/views_port_scanner.py` | `port_scanner_home()`, `start_port_scan()`, `port_scanner_results()`, `port_scanner_status()` |
| `dashboard/scanner/models.py` | Database models for storing scan results and port information |

#### Port Scanner Class (Dashboard-Side)

##### Location

`dashboard/scanner/port_scanner.py`

##### Class Initialization

```python
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
```

##### Key Methods

###### start_scan(process_id=None)

**Purpose**: Initiates the port scanning process

**Parameters**:
- **process_id**: Optional process ID for state management

**Implementation Details**:
- Creates a new scan record in the database
- Registers the scan with the state manager
- Starts the scan in a separate thread
- Returns success/failure status

###### _run_scan()

**Purpose**: Main scanning method that coordinates the scanning process

**Implementation Details**:
- Attempts to use agent-based scanning first
- Falls back to local scanning if agent communication fails
- Updates scan progress and status
- Records scan results in the database

###### _run_nmap_scan(port_range_str)

**Purpose**: Performs port scanning using Nmap

**Parameters**:
- **port_range_str**: String representation of port range to scan

**Implementation Details**:
- Uses python-nmap library for scanning
- Configures scan parameters based on scan type
- Monitors scan progress
- Processes and stores scan results

###### _run_custom_scan(port_range_str)

**Purpose**: Performs port scanning using custom socket-based implementation

**Parameters**:
- **port_range_str**: String representation of port range to scan

**Implementation Details**:
- Uses Python sockets for port checking
- Implements service detection through banner grabbing
- Updates progress during scanning
- Processes and stores scan results

#### Scan Types

##### Quick Scan

**Port Range**: 21-23,25,53,80,443,3389,8080
**Nmap Arguments**: -sV --version-intensity 2 -T4
**Purpose**: Fast scan of common ports
**Use Case**: Initial reconnaissance

##### Standard Scan

**Port Range**: 1-1024
**Nmap Arguments**: -sV -O --version-intensity 5 -T4
**Purpose**: Comprehensive scan of well-known ports
**Use Case**: Regular security assessment

##### Comprehensive Scan

**Port Range**: 1-65535
**Nmap Arguments**: -sV -O -A --version-all --version-intensity 9 -T4 --script="banner,version,discovery"
**Purpose**: Thorough scan of all ports
**Use Case**: Detailed security assessment

##### Custom Scan

**Port Range**: User-defined
**Nmap Arguments**: User-defined
**Purpose**: Specialized scanning based on user requirements
**Use Case**: Targeted security assessment

#### Output

The port scanning functionality produces detailed reports of open ports and running services. The output is designed to be:
- Summarized with key statistics about the scan
- Categorized by service type for easier analysis
- Detailed, providing port numbers, services, versions, and banners
- Visual, using color-coding and badges to highlight important information

**Screenshots to add**:
1. **Port Scan Summary**: Add a screenshot showing the summary cards with counts of Open Ports, Identified Services, Potentially Risky Services, and Scan Method
2. **Services by Category**: Add a screenshot showing the grouping of services by category (Web Services, Database Services, Remote Access, etc.)
3. **All Open Ports**: Add a screenshot showing the detailed table of all open ports with columns for Port, Protocol, Service, Version, Banner, and Actions

*Note: The actual output will vary based on the target system and the ports/services discovered during the scan.*

### 11.5 Network Monitoring

#### Introduction

The network monitoring functionality in ShadowPulse Scanner provides real-time analysis of network traffic to detect security issues, monitor bandwidth usage, and identify anomalous network behavior. Unlike other components that run on target systems, the network monitoring runs on the host machine to analyze local network traffic. This component is essential for detecting ongoing attacks, unusual network behavior, and potential data exfiltration.

#### Application Used

The network monitoring functionality is used in the following scenarios:

- Real-time security monitoring
- Network traffic analysis
- Bandwidth usage monitoring
- Anomaly detection
- Intrusion detection
- Data exfiltration prevention
- Network forensics

#### Source Functions

The network monitoring functionality is implemented across multiple files:

| File | Key Functions |
|------|---------------|
| `dashboard/scanner/network_monitor.py` | `start_monitoring()`, `stop_monitoring()`, `_capture_packets()`, `_process_packet()`, `_analyze_traffic()`, `_detect_port_scanning()`, `_create_alert()`, `get_statistics()` |
| `dashboard/scanner/views_monitoring.py` | `network_monitor_dashboard()`, `start_network_monitor()`, `stop_network_monitor()`, `network_monitor_stats()`, `network_alerts()`, `resolve_alert()` |
| `dashboard/scanner/models.py` | Database models for storing monitoring logs, traffic statistics, and alerts |

#### Network Monitor Class

##### Location

`dashboard/scanner/network_monitor.py`

##### Class Initialization

```python
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

    # Initialize statistics
    self.stats = {
        'packets_captured': 0,
        'bytes_captured': 0,
        'start_time': None,
        'last_update': None
    }

    # Initialize data structures
    self.recent_packets = deque(maxlen=max_packets)
    self.packet_sizes = deque(maxlen=1000)
    self.protocol_counts = defaultdict(int)
    self.ip_connections = defaultdict(int)
    self.port_activity = defaultdict(int)
    self.dns_queries = defaultdict(int)
    self.http_hosts = defaultdict(int)

    # Load threat intelligence
    self._load_threat_intelligence()
```

##### Key Methods

###### start_monitoring()

**Purpose**: Starts the network monitoring process

**Implementation Details**:
- Sets running flag to True
- Records start time
- Registers with state manager
- Starts packet capture thread
- Starts analysis thread
- Logs the start of monitoring
- Returns success/failure status

###### stop_monitoring()

**Purpose**: Stops the network monitoring process

**Implementation Details**:
- Sets running flag to False
- Waits for threads to terminate
- Logs the stop of monitoring
- Returns success/failure status

###### _capture_packets()

**Purpose**: Captures network packets using scapy

**Implementation Details**:
- Uses Scapy's sniff function to capture packets
- Continues capturing until running flag is False
- Handles exceptions and logs errors

###### _process_packet(packet)

**Purpose**: Processes a captured packet

**Parameters**:
- **packet**: Scapy packet object

**Implementation Details**:
- Updates basic statistics
- Stores packet for later analysis
- Analyzes packet based on protocol
- Checks for known malicious IPs and domains
- Updates connection tracking
- Records protocol information

###### _analyze_traffic()

**Purpose**: Periodically analyzes traffic patterns to detect anomalies

**Implementation Details**:
- Runs in a loop while monitoring is active
- Updates traffic statistics in database
- Detects port scanning
- Detects unusual traffic patterns
- Detects data exfiltration
- Handles exceptions and logs errors

###### _detect_port_scanning()

**Purpose**: Detects potential port scanning activity

**Implementation Details**:
- Analyzes connection patterns
- Looks for multiple connection attempts to different ports
- Creates alerts for suspected port scanning
- Updates database with scan information

#### Features

##### Real-time Packet Capture

- Uses Scapy for packet capture
- Supports multiple network interfaces
- Captures all network protocols
- Stores recent packets for analysis

##### Traffic Analysis

- Protocol distribution tracking
- Bandwidth usage monitoring
- Connection tracking
- Service usage statistics

##### Security Monitoring

- Port scan detection
- Malicious IP/domain detection
- Data exfiltration detection
- Unusual traffic pattern identification

##### Alerting

- Real-time alert generation
- Multiple severity levels
- Detailed alert information
- Alert management interface

#### Output

The network monitoring functionality produces real-time statistics and alerts. The output is designed to be:
- Visual, with charts and graphs for traffic analysis
- Real-time, with continuously updating statistics
- Comprehensive, showing traffic patterns, protocol distribution, and alerts
- Actionable, with alert management capabilities

**Screenshots to add**:
1. **Traffic Overview**: Add a screenshot showing the traffic overview chart displaying bandwidth usage over time
2. **Protocol Distribution**: Add a screenshot showing the protocol distribution pie chart or bar graph
3. **Network Statistics**: Add a screenshot showing the summary cards with Current Bandwidth, Packets Captured, Active Connections, and Security Alerts
4. **Security Alerts**: Add a screenshot showing the table of security alerts with columns for Time, Alert Type, Severity, Source IP, Destination IP, Description, and Actions

*Note: The actual output includes interactive charts that update in real-time as network traffic is monitored.*

### 11.6 ZAMBOT Protocol

#### Introduction

The ZAMBOT protocol is a custom binary protocol used for communication between the ShadowPulse Scanner dashboard and agent components. It provides a structured, efficient, and secure method for sending commands and receiving responses. This protocol is the foundation of the client-server architecture, enabling reliable and efficient communication between the dashboard and agents.

#### Application Used

The ZAMBOT protocol is used in the following scenarios:

- Command transmission from dashboard to agents
- Data collection from target systems
- Security scan coordination
- System information retrieval
- Network reconnaissance operations
- Vulnerability assessment communication
- Status and progress reporting

#### Source Functions

The ZAMBOT protocol is implemented across multiple files:

| File | Key Functions |
|------|---------------|
| `proto/pro/protocol.py` | Protocol constants and structure definitions |
| `proto/host/host_controller.py` | `send_request()`, `receive_response()` |
| `proto/agent/agent_listener.py` | `handle_client()`, `process_request()` |

#### Protocol Specification

##### Header Structure

The ZAMBOT protocol uses a 19-byte header with the following structure:

```
+----------------+----------+--------+------------+-------------+----------------+----------+
| Magic Header   | Version  | Flags  | Request ID | Command     | Payload Length | Reserved |
| (6 bytes)      | (1 byte) | (1 byte)| (4 bytes) | (1 byte)    | (4 bytes)      | (2 bytes)|
+----------------+----------+--------+------------+-------------+----------------+----------+
```

###### Header Fields

- **Magic Header (6 bytes)**: Always 'ZAMBOT' (ASCII)
- **Version (1 byte)**: Protocol version number (currently 0x01)
- **Flags (1 byte)**: Control flags for special handling
- **Request ID (4 bytes)**: Unique identifier for the request
- **Command Code (1 byte)**: Operation code indicating the command to execute
- **Payload Length (4 bytes)**: Length of the payload in bytes
- **Reserved (2 bytes)**: Reserved for future use

##### Flag Bits

- **FLAG_COMPRESSED (0x01)**: Indicates that the payload is compressed with zlib

##### Message Format

A complete ZAMBOT message consists of a header followed by an optional payload:

```
+----------------+-------------------+
| Header         | Payload           |
| (19 bytes)     | (variable length) |
+----------------+-------------------+
```

#### Command Codes

The ZAMBOT protocol defines several categories of command codes:

##### Basic Commands (0x01-0x0F)

- **CMD_OS_INFO (0x01)**: Get basic OS information
- **CMD_LIST_PRODUCTS (0x02)**: List installed products
- **CMD_NETWORK_SCAN (0x03)**: Perform network scan
- **CMD_SYSTEM_DIAG (0x04)**: Perform system diagnostics
- **CMD_FULL_OS_INFO (0x05)**: Get full OS information
- **CMD_FULL_NETWORK_INFO (0x06)**: Get full network information
- **CMD_GET_POWERSHELL_HISTORY (0x07)**: Get PowerShell command history
- **CMD_GET_OS_INFO_SECTION (0x08)**: Get a specific section of OS info

##### OS Info Commands (0x10-0x2F)

- **CMD_GET_OS_INFO (0x10)**: Get detailed OS information
- **CMD_GET_AMSI_PROVIDERS (0x11)**: Get AMSI providers
- **CMD_GET_REGISTERED_ANTIVIRUS (0x12)**: Get registered antivirus products
- **CMD_GET_WINDOWS_DEFENDER_SETTINGS (0x13)**: Get Windows Defender settings
- **CMD_GET_AUTO_RUN_EXECUTABLES (0x14)**: Get auto-run executables
- **CMD_GET_CERTIFICATES (0x15)**: Get certificates
- **CMD_GET_ENVIRONMENT_VARIABLES (0x16)**: Get environment variables
- **CMD_LIST_USER_FOLDERS (0x17)**: List user folders
- **CMD_GET_FILE_VERSION (0x18)**: Get file version information
- **CMD_GET_INSTALLED_HOTFIXES (0x19)**: Get installed hotfixes
- **CMD_GET_INSTALLED_PRODUCTS (0x1A)**: Get installed products
- **CMD_GET_NON_EMPTY_LOCAL_GROUPS (0x1B)**: Get non-empty local groups
- **CMD_GET_LOCAL_USERS (0x1C)**: Get local users
- **CMD_GET_MS_UPDATES (0x1D)**: Get Microsoft updates
- **CMD_GET_NTLM_SETTINGS (0x1E)**: Get NTLM settings
- **CMD_GET_RDP_CONNECTIONS (0x1F)**: Get RDP connections
- **CMD_GET_SECURE_BOOT_INFO (0x20)**: Get secure boot information
- **CMD_GET_SYSMON_CONFIG (0x21)**: Get Sysmon configuration
- **CMD_GET_UAC_POLICIES (0x22)**: Get UAC policies
- **CMD_GET_AUDIT_POLICY (0x23)**: Get audit policy
- **CMD_GET_FIREWALL_RULES (0x24)**: Get firewall rules
- **CMD_GET_RUNNING_PROCESSES (0x25)**: Get running processes

##### Network Info Commands (0x30-0x4F)

- **CMD_ARP_SCAN (0x30)**: Perform ARP scan
- **CMD_DNS_CACHE (0x31)**: Get DNS cache
- **CMD_WINDOWS_NETWORK_PROFILE (0x32)**: Get Windows network profile
- **CMD_NETWORK_SHARES (0x33)**: Get network shares
- **CMD_TCP_UDP_CONNECTIONS (0x34)**: Get TCP/UDP connections
- **CMD_RPC_SERVICE_CHECK (0x35)**: Check RPC services
- **CMD_PORT_SCANNER (0x36)**: Scan ports
- **CMD_BANNER_GRABBER (0x37)**: Grab service banners
- **CMD_PORT_SCAN (0x38)**: Comprehensive port scan with service detection

##### Memory Protection Analysis (0x40-0x4F)

- **CMD_ANALYZE_PROCESS_MEMORY (0x40)**: Analyze process memory

##### Vulnerability Scanning (0x50-0x5F)

- **CMD_VULNERABILITY_SCAN (0x50)**: Perform vulnerability scan

#### Implementation

The protocol is defined in `proto/pro/protocol.py` and implemented in the following files:

- **Protocol Definition**: `proto/pro/protocol.py`
- **Client-Side Implementation**: `proto/host/host_controller.py`
- **Server-Side Implementation**: `proto/agent/agent_listener.py`

#### Data Handling

- **Large Responses**: Responses larger than 10KB are automatically compressed using zlib
- **Chunking**: Large responses are sent in chunks of up to 4KB
- **Timeouts**: Default timeout for requests is 30 seconds
- **Error Handling**: Comprehensive error handling for network issues, malformed requests, and timeouts

#### Output

The ZAMBOT protocol itself doesn't produce visual output, but its operation can be visualized through packet captures and debug logs. Below is an example of a protocol exchange:

```
[DEBUG] Sending ZAMBOT request:
  Magic Header: ZAMBOT
  Version: 0x01
  Flags: 0x00
  Request ID: 0x1A2B3C4D
  Command Code: 0x01 (CMD_OS_INFO)
  Payload Length: 0
  Reserved: 0x0000

[DEBUG] Raw request bytes:
  5A 41 4D 42 4F 54 01 00 1A 2B 3C 4D 01 00 00 00 00 00 00

[DEBUG] Received ZAMBOT response:
  Magic Header: ZAMBOT
  Version: 0x01
  Flags: 0x01 (FLAG_COMPRESSED)
  Request ID: 0x1A2B3C4D
  Status: 0x00 (Success)
  Payload Length: 8192
  Reserved: 0x0000

[DEBUG] Decompressing response payload...
[DEBUG] Decompressed payload size: 24576 bytes
[DEBUG] Response contains HTML-formatted system information
```

The protocol communication is designed to be:
- Efficient, with minimal overhead for small requests
- Scalable, with compression for large responses
- Reliable, with request ID tracking and error handling
- Secure, with validation of all message components

When monitoring protocol traffic, the exchange looks like this:

[ZAMBOT Protocol Exchange Diagram]

*Note: The actual protocol exchange is binary and not human-readable without special tools. The above representation is a debug view of the protocol operation.*

## 12. Project Structure and Files

### 12.1 Template Structure

The ShadowPulse Scanner uses Django's template system for rendering HTML pages. The templates are organized in the `dashboard/scanner/templates/scanner/` directory:

#### Base Templates
- **base.html**: Main template with navigation, sidebar, and common styling
  - Includes the main layout, navigation bar, and sidebar menu
  - Contains common CSS styles and JavaScript includes
  - Uses the rex-logo.svg for branding

- **base_auth.html**: Template for authentication pages (login, registration)
  - Simplified layout without navigation sidebar
  - Contains authentication-specific styling
  - Includes marketing content about Rex Security features

#### Page Templates
- **index.html**: Dashboard home page with system overview
- **target_list.html**: List of target systems
- **target_detail.html**: Detailed view of a target system
- **os_info.html**: System information display
- **network_info.html**: Network information display
- **port_scanner_home.html**: Port scanner interface
- **port_scanner_results.html**: Port scan results display
- **port_scanner_history.html**: History of port scans
- **vulnerability_checkup_home.html**: Vulnerability scanner interface
- **vulnerability_checkup_detail.html**: Detailed vulnerability scan results
- **network_monitor.html**: Network monitoring interface
- **help_support.html**: Help and support documentation

#### Template Tags and Filters

Custom template tags and filters are defined in `dashboard/scanner/templatetags/scanner_filters.py`:

- **split**: Splits a string by the given argument
- **get_item**: Gets an item from a list by index or from a dictionary by key
- **trim**: Trims whitespace from a string

### 12.2 Static Files

Static files are stored in the `dashboard/scanner/static/scanner/` directory:

#### CSS
- **custom.css**: Custom styling for the application
- **dark-theme.css**: Dark theme styling

#### JavaScript
- **data-persistence.js**: Client-side data persistence using localStorage
- **chart-utils.js**: Utilities for creating charts and graphs
- **scan-progress.js**: Handles scan progress updates
- **network-monitor.js**: Network monitoring functionality
- **port-scanner.js**: Port scanning functionality
- **vulnerability-scanner.js**: Vulnerability scanning functionality

#### Images
- **rex-logo.svg**: Main application logo
- **icons/**: Directory containing various icons used in the application

### 12.3 Other Important Files

- **dashboard/scanner/urls.py**: URL routing for the scanner application
- **dashboard/dashboard/urls.py**: Main URL routing for the project
- **dashboard/dashboard/settings.py**: Development settings
- **dashboard/dashboard/settings_prod.py**: Production settings
- **proto/pro/protocol.py**: ZAMBOT protocol implementation
- **proto/agent/agent_listener.py**: Agent listener implementation
- **proto/agent/handlers.py**: Command handlers for the agent
- **proto/host/host_controller.py**: Host controller implementation
- **build_agent_exe.py**: Script to build the agent executable
- **docker-compose.yml**: Docker configuration for production deployment
- **.env.example**: Example environment variables

## 13. Market Comparison and Advantages

### 13.1 Competitive Analysis

ShadowPulse Scanner offers several key advantages over existing security assessment tools in the market:

#### Comparison with Commercial Solutions

| Feature | ShadowPulse Scanner | Nessus | OpenVAS | Qualys | Nexpose |
|---------|---------------------|--------|---------|--------|---------|
| Comprehensive Scanning | ✓ | ✓ | ✓ | ✓ | ✓ |
| Agent-Based Architecture | ✓ | Partial | No | ✓ | Partial |
| Real-time Network Monitoring | ✓ | No | No | Limited | No |
| Customizable Scanning | ✓ | Limited | Limited | ✓ | ✓ |
| Dark Mode UI | ✓ | No | No | No | No |
| Open Source | ✓ | No | ✓ | No | No |
| Pricing | Free | $$$$ | Free | $$$$ | $$$$ |

### 13.2 Key Differentiators

#### 1. Unified Platform

Unlike many competitors that offer separate tools for different security functions, ShadowPulse Scanner provides a unified platform that integrates:
- Vulnerability scanning
- Port scanning
- Network monitoring
- System information collection
- Security alerting

This integration eliminates the need for multiple tools and provides a cohesive security assessment experience.

#### 2. Agent-Based Architecture

ShadowPulse Scanner's agent-based architecture offers several advantages:
- More accurate scanning results by running directly on target systems
- Ability to scan systems behind firewalls and NAT
- Reduced network traffic compared to network-based scanners
- Persistent monitoring capabilities
- Ability to perform offline scans

#### 3. Modern User Interface

The dashboard features a modern, intuitive interface with:
- Dark mode support for reduced eye strain
- Real-time data visualization
- Interactive charts and graphs
- Mobile-responsive design
- Customizable dashboards

#### 4. Extensibility

ShadowPulse Scanner is designed to be highly extensible:
- Modular architecture allows for easy addition of new scanning capabilities
- API-first design enables integration with other security tools
- Plugin system for custom vulnerability checks
- Support for custom reporting templates

#### 5. Cost-Effectiveness

As an open-source solution, ShadowPulse Scanner offers enterprise-grade security assessment capabilities without the high cost of commercial alternatives:
- No licensing fees
- No per-scan or per-host charges
- No feature limitations in the free version
- Community-supported development and updates

### 13.3 Target Market

ShadowPulse Scanner is ideal for:

- **Small to Medium Businesses**: Organizations that need comprehensive security assessment but can't afford expensive commercial solutions
- **Security Consultants**: Professionals who need a flexible, customizable tool for client assessments
- **Educational Institutions**: Universities and training centers teaching cybersecurity concepts
- **Security Researchers**: Individuals conducting security research and vulnerability discovery
- **DevSecOps Teams**: Development teams implementing security in CI/CD pipelines

