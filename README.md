# 🔍 ShadowPulse Scanner 

<div align="center">
  <img src="docs/images/rex-logo.svg" alt="ShadowPulse Scanner Logo" width="180" height="180">
  <h3>Advanced Security Assessment & Vulnerability Management Platform</h3>

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Django Version](https://img.shields.io/badge/django-4.2-green.svg)](https://www.djangoproject.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/yourusername/rex-security)

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Setup Instructions](#setup-instructions)
  - [Configuration](#configuration)
- [Usage Guide](#-usage-guide)
  - [Dashboard Overview](#dashboard-overview)
  - [Target Management](#target-management)
  - [Scanning Operations](#scanning-operations)
  - [Report Generation](#report-generation)
- [Agent Deployment](#-agent-deployment)
  - [Building the Agent Executable](#building-the-agent-executable)
  - [Running the Agent](#running-the-agent)
  - [Agent Configuration](#agent-configuration)
- [Technical Documentation](#-technical-documentation)
  - [Agent-Controller Protocol](#agent-controller-protocol)
  - [Database Schema](#database-schema)
  - [API Reference](#api-reference)
- [Security Considerations](#-security-considerations)
- [Development](#-development)
  - [Project Structure](#project-structure)
  - [Contributing Guidelines](#contributing-guidelines)
  - [Testing](#testing)
- [Roadmap](#-roadmap)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)

## 🔎 Overview

Rex Security Scanner is an enterprise-grade security assessment and vulnerability management platform designed to provide comprehensive security analysis for networked systems. Built with a modern client-server architecture, Rex enables security professionals to identify, analyze, and remediate security vulnerabilities across their infrastructure.

The platform combines real-time monitoring, detailed system intelligence gathering, and advanced vulnerability detection to deliver actionable security insights through an intuitive web-based dashboard.

## ✨ Key Features

### 🛡️ Comprehensive Security Analysis
- **Vulnerability Assessment**: Identify and categorize security vulnerabilities with severity ratings
- **AMSI Provider Detection**: Analyze Anti-Malware Scan Interface providers and configurations
- **Antivirus Analysis**: Evaluate antivirus solutions and their effectiveness
- **Security Audit Policies**: Review and validate security audit configurations
- **UAC Settings Verification**: Ensure User Account Control settings meet security standards
- **System Certificates Analysis**: Inspect certificate stores for expired or untrusted certificates
- **Firewall Rule Analysis**: Comprehensive review of firewall configurations and rule sets

### 🔒 Vulnerability Scanning System
- **Multi-level Scanning**: Quick, standard, and deep vulnerability scanning options
- **Service Vulnerability Detection**: Identify vulnerabilities in running services
- **OS Vulnerability Assessment**: Detect operating system security issues
- **Web Application Scanning**: Check for common web vulnerabilities
- **Network Configuration Analysis**: Identify insecure network configurations
- **CVE Database Integration**: Match findings against known Common Vulnerabilities and Exposures
- **Remediation Guidance**: Detailed steps for addressing identified vulnerabilities
- **Vulnerability Tracking**: Monitor the status of vulnerabilities through remediation lifecycle

### 🔍 System Intelligence
- **OS Information Collection**: Detailed operating system information and configuration analysis
- **Software Inventory**: Complete inventory of installed software with version tracking
- **Environment Analysis**: Evaluation of system environment variables and configurations
- **User & Group Enumeration**: Comprehensive mapping of users, groups, and permissions
- **PowerShell History Analysis**: Review of PowerShell command history for security implications
- **Running Process Monitoring**: Real-time analysis of running processes and services
- **Startup Program Analysis**: Identification of programs configured to run at system startup

### 🌐 Network Reconnaissance
- **Network Device Discovery**: Automatic discovery of devices on the network
- **ARP Scanning**: Layer 2 network mapping capabilities
- **Service Discovery**: Identification of running services on network devices
- **Port Analysis**: Comprehensive port scanning with service identification
- **DNS Cache Inspection**: Analysis of DNS cache for potential security issues
- **Network Share Mapping**: Discovery and security assessment of network shares
- **Network Traffic Analysis**: Monitoring of network traffic patterns for anomaly detection

### 🔍 Network Monitoring System
- **Real-time Traffic Analysis**: Capture and analyze network traffic on the host machine
- **Protocol Distribution Visualization**: Visual breakdown of network protocols in use
- **Anomaly Detection**: Identify unusual patterns in network traffic
- **Security Alert Generation**: Automatic alerts for suspicious network activity
- **Threat Intelligence Integration**: Detection of known malicious IPs and domains
- **Traffic Statistics**: Track packets, bytes, and connections over time
- **Top Talkers Identification**: Identify most active hosts on the network

### 📊 Reporting & Analytics
- **Interactive Dashboard**: Real-time security posture visualization
- **Customizable Reports**: Generate detailed reports tailored to different stakeholders
- **Trend Analysis**: Track security metrics over time to identify patterns
- **Risk Scoring**: Quantitative risk assessment based on multiple security factors
- **Compliance Reporting**: Pre-configured reports for common compliance frameworks
- **Remediation Tracking**: Monitor progress of security issue remediation efforts

## 🏗️ System Architecture

Rex Security Scanner employs a distributed architecture consisting of three main components:

### 🖥️ Dashboard Component
- **Web-Based Interface**: Modern Django-based web application
- **Real-Time Visualization**: Interactive charts and graphs for security metrics
- **User Management**: Role-based access control with multi-user support
- **Notification System**: Alerts for critical security events
- **Report Generation Engine**: Flexible reporting capabilities
- **RESTful API**: Programmatic access to security data

### 🎮 Controller Component
- **Command & Control Center**: Centralized management of security operations
- **Target Management**: Inventory and organization of target systems
- **Scan Orchestration**: Coordination of scanning activities across multiple targets
- **Data Processing Pipeline**: Processing and analysis of security data
- **Result Aggregation**: Consolidation of findings from multiple sources
- **Scheduling System**: Automated execution of security assessments

### 🤖 Agent Component
- **Lightweight Client**: Efficient agent that runs on target systems
- **TCP Server (Port 23033)**: Communication endpoint for controller interaction
- **Modular Assessment Engine**: Pluggable security assessment modules
- **System Monitoring**: Real-time monitoring of system changes
- **Data Collection**: Efficient gathering of system and security information
- **Self-Protection**: Mechanisms to prevent tampering with the agent

## 📥 Installation

### Prerequisites
- Python 3.8 or higher
- Django 4.2 or higher
- PostgreSQL 12+ (recommended for production) or SQLite (development)
- Modern web browser (Chrome, Firefox, Edge, Safari)
- Network connectivity between controller and target systems
- Administrative privileges on target systems (for agent installation)

### Setup Instructions

#### Dashboard & Controller Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/rex-security.git
   cd rex-security
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On Linux/macOS
   source venv/bin/activate
   ```

3. **Install required packages**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   cd dashboard
   python manage.py migrate
   ```

5. **Create an administrator account**
   ```bash
   python manage.py createsuperuser
   ```

6. **Start the development server**
   ```bash
   python manage.py runserver
   ```

7. **Access the dashboard**
   Open your browser and navigate to `http://127.0.0.1:8000/`

### Running the Web Application

The ShadowPulse Scanner web application is built with Django and provides a comprehensive interface for security assessment and vulnerability management.

#### Development Mode

1. **Start the Django Development Server**
   ```bash
   cd dashboard
   python manage.py runserver
   ```
   This will start the development server on http://127.0.0.1:8000/

2. **Access the Web Interface**
   - Open your browser and navigate to http://127.0.0.1:8000/
   - Log in with your administrator account
   - You'll be redirected to the main dashboard

#### Production Mode

1. **Configure Production Settings**
   - Copy `.env.example` to `.env` and configure settings
   - Set secure passwords and a proper secret key
   - Configure allowed hosts for your domain

2. **Using Docker Compose (Recommended)**
   ```bash
   # Development mode
   docker-compose up -d

   # Production mode
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```

   This will:
   - Start the web application, PostgreSQL database, Redis cache, and Nginx
   - Apply database migrations automatically
   - Collect static files
   - Configure proper networking between services

3. **Docker Deployment Features**
   - Automatic database initialization and migration
   - Health checks for all services
   - Resource limits for production deployment
   - Nginx configuration for static files and proxying
   - Separate development and production configurations
   - SSL support (requires certificates)

4. **Accessing the Application**
   - Development: http://localhost:8000/ (direct Django access)
   - Production: http://localhost/ (through Nginx)
   - Admin interface: http://localhost/admin/

5. **Manual Production Deployment (Alternative)**
   ```bash
   cd dashboard
   python manage.py collectstatic
   gunicorn dashboard.wsgi_prod:application
   ```

6. **Docker Deployment Documentation**
   - See `DOCKER_README.md` for detailed Docker deployment instructions
   - Includes configuration, management, and troubleshooting information

## 🤖 Agent Deployment

The ShadowPulse Scanner uses an agent-based architecture where the agent component runs on target systems and communicates with the central dashboard. The agent can be deployed as either a Python module or a standalone executable.

### Building the Agent Executable

The agent can now be built as a standalone executable, eliminating the need for Python to be installed on target systems.

1. **Using the Build Script**
   ```bash
   # Run the build script
   python build_agent_exe.py

   # Or use the batch file on Windows
   build_agent.bat
   ```

2. **What the Build Process Does**
   - Checks for and installs required dependencies (PyInstaller, scapy, mac_vendor_lookup, wmi)
   - Creates a temporary entry point script
   - Packages all necessary files into a single executable
   - Places the executable in the current directory

3. **Build Requirements**
   - Python 3.8 or higher
   - Internet connection (for downloading dependencies)
   - PyInstaller (installed automatically if missing)
   - Sufficient disk space (~50-100MB for the build process)

### Running the Agent

1. **Using the Executable**
   ```bash
   # Simply run the executable
   agent_listener.exe
   ```

2. **Using Python Module (Alternative)**
   ```bash
   # Run as a Python module
   python -m proto.agent.agent_listener
   ```

3. **Verifying Operation**
   - The agent will display `[+] Agent listening on 0.0.0.0:23033` when started successfully
   - The HTTP server will show `[HTTP] Server started on http://0.0.0.0:23033`
   - The agent is now ready to accept connections from the dashboard

### Agent Configuration

1. **Network Configuration**
   - The agent listens on port 23033 by default (both TCP socket and HTTP)
   - Ensure this port is accessible from the dashboard system
   - Firewall rules may need to be adjusted to allow incoming connections

2. **Security Considerations**
   - The agent provides access to system information and should only be run on trusted systems
   - Consider network segmentation to limit access to the agent
   - The agent does not implement authentication by default; use network security measures

3. **Connecting from Dashboard**
   - Add the agent's IP address as a target in the dashboard
   - The dashboard will automatically connect to the agent on port 23033
   - Verify connectivity by running a basic scan from the dashboard

### Configuration

#### Dashboard Configuration
Edit `dashboard/dashboard/settings.py` to customize:
- Database settings
- Authentication options
- Email notifications
- Logging preferences
- Security settings

#### Agent Configuration
Edit `agent/config.ini` on target systems to set:
- Controller connection details
- Scan permissions
- Resource usage limits
- Logging options
- Self-protection features

## 🖱️ Usage Guide

### Dashboard Overview

The ShadowPulse Scanner dashboard provides a comprehensive view of your security posture:

1. **Home Dashboard**
   - Security score overview
   - Recent scan activity
   - Critical vulnerability alerts
   - System status indicators
   - Quick action buttons

2. **Navigation**
   - Left sidebar menu organizes key functions
   - Top navigation for user settings and global actions
   - Breadcrumb navigation for deep pages

### Web Application Features

The ShadowPulse Scanner web application provides a comprehensive set of security assessment and monitoring features:

#### OS Information

The OS Information module provides detailed information about target systems:

- **System Overview**: Basic system information including OS version, hostname, and architecture
- **Operating System Details**: Detailed OS configuration and settings
- **Environment Variables**: System and user environment variables
- **User Folders**: List of user folders and permissions
- **Installed Software**: Comprehensive inventory of installed applications
- **Windows Updates**: Status of installed updates and patches
- **Audit Policy**: System audit policy configuration
- **Full System Report**: Generate a complete system report with all sections

#### Network Monitoring

The Network Monitoring module provides real-time network analysis:

- **Network Devices**: Discovery of devices on the network
- **Traffic Analysis**: Monitoring of network traffic patterns
- **Connection Tracking**: Active network connections
- **Security Alerts**: Detection of suspicious network activity
- **Network Visualization**: Visual representation of network topology

#### Port Scanner

The Port Scanner module provides comprehensive port scanning capabilities:

- **Standard Scan**: Quick scan of common ports
- **Full Scan**: Comprehensive scan of all ports
- **Service Detection**: Identification of services running on open ports
- **Banner Grabbing**: Collection of service banners for fingerprinting
- **Vulnerability Correlation**: Linking open ports to potential vulnerabilities

#### Vulnerability Management

The Vulnerability Management module identifies and tracks security vulnerabilities:

- **Software Vulnerability Scanning**: Check installed software against known vulnerabilities
- **System Configuration Analysis**: Identify security misconfigurations
- **Vulnerability Tracking**: Monitor the status of identified vulnerabilities
- **Remediation Guidance**: Recommendations for addressing vulnerabilities
- **Risk Scoring**: Prioritization based on severity and impact

### Target Management

1. **Adding Targets**
   - Click "Add Target" button
   - Enter IP address or hostname
   - Select scan profile
   - Initiate agent deployment if needed

2. **Organizing Targets**
   - Group targets by department, location, or function
   - Apply tags for flexible categorization
   - Set priority levels for scanning and remediation

3. **Target Details**
   - System information
   - Vulnerability history
   - Scan history
   - Remediation status

### Scanning Operations

1. **Scan Types**
   - Quick Scan: Basic security check (5-10 minutes)
   - Standard Scan: Comprehensive assessment (15-30 minutes)
   - Deep Scan: Thorough security analysis (30-60 minutes)
   - Custom Scan: User-defined assessment parameters

2. **Scheduling Scans**
   - One-time immediate execution
   - Recurring schedules (daily, weekly, monthly)
   - Maintenance window alignment
   - Low-impact scanning options

3. **Scan Results**
   - Vulnerability listings with severity ratings
   - Detailed finding explanations
   - Remediation recommendations
   - False positive management
   - Historical comparison

### Report Generation

1. **Report Types**
   - Executive Summary
   - Technical Detail Report
   - Compliance Report
   - Remediation Planning Report
   - Trend Analysis Report

2. **Export Options**
   - PDF format for formal documentation
   - CSV/Excel for data analysis
   - HTML for web sharing
   - JSON for integration with other tools

3. **Scheduling & Distribution**
   - Automated report generation
   - Email distribution to stakeholders
   - Secure report access controls
   - Report archiving and retention

## 📚 Technical Documentation

### How the System Works

ShadowPulse Scanner operates as a client-server system with three main components:

1. **Dashboard (Web Interface)**
   - Django-based web application that provides the user interface
   - Manages targets, scans, and results
   - Visualizes security data and generates reports
   - Communicates with agents through the host controller

2. **Host Controller**
   - Manages communication between the dashboard and agents
   - Sends commands to agents and processes responses
   - Implements the client side of the ZAMBOT protocol
   - Located in `proto/host/host_controller.py`

3. **Agent**
   - Runs on target systems to collect security information
   - Implements various security assessment modules
   - Provides both socket and HTTP interfaces
   - Can be run as Python module or standalone executable
   - Located in `proto/agent/agent_listener.py`

### Application Flow

1. **User Interaction**
   - User accesses the dashboard web interface
   - Adds target systems (IP addresses where agents are running)
   - Initiates scans or security assessments

2. **Command Execution**
   - Dashboard sends command to host controller
   - Host controller formats command using ZAMBOT protocol
   - Command is sent to the appropriate agent
   - Agent processes command and returns results
   - Results are displayed in the dashboard

3. **Data Storage**
   - Scan results are stored in the database
   - Vulnerabilities and security issues are tracked
   - Historical data is maintained for trend analysis

### Agent-Controller Protocol

The system uses a custom binary protocol (ZAMBOT) for efficient and reliable communication between the controller and agents:

#### Protocol Overview

- **Name**: ZAMBOT Protocol
- **Transport**: TCP (port 23033 by default)
- **Format**: Binary with structured header and payload
- **Features**: Command codes, compression, request IDs

#### Packet Structure

**Request Format (Controller → Agent)**
| Field          | Size    | Description              |
|----------------|---------|--------------------------|
| Magic Header   | 6 bytes | 'ZAMBOT'                |
| Version        | 1 byte  | Protocol version        |
| Flags          | 1 byte  | Control flags           |
| Request ID     | 4 bytes | Unique identifier       |
| Command Code   | 1 byte  | Operation code          |
| Payload Length | 4 bytes | Data length             |
| Reserved       | 2 bytes | Future use              |
| Payload        | Variable| Command data            |

**Response Format (Agent → Controller)**
| Field          | Size    | Description              |
|----------------|---------|--------------------------|
| Magic Header   | 6 bytes | 'ZAMBOT'                |
| Version        | 1 byte  | Protocol version        |
| Flags          | 1 byte  | Control flags           |
| Request ID     | 4 bytes | Matches request         |
| Status Code    | 1 byte  | Operation result        |
| Payload Length | 4 bytes | Response length         |
| Reserved       | 2 bytes | Future use              |
| Payload        | Variable| Response data           |

#### Command Reference

| Code  | Operation              | Description                    |
|-------|------------------------|--------------------------------|
| 0x01  | Basic OS Info         | Core system information        |
| 0x02  | Software Inventory    | Installed products scan        |
| 0x03  | Network Scan          | Network reconnaissance         |
| 0x04  | System Diagnostics    | System health check            |
| 0x05  | Full OS Info          | Detailed system analysis       |
| 0x06  | Network Details       | Comprehensive network data     |
| 0x07  | PowerShell Analysis   | Command history & settings     |
| 0x08  | Process Enumeration   | Running process details        |
| 0x09  | Service Analysis      | Service configuration review   |
| 0x0A  | User Management       | User and group analysis        |
| 0x0B  | File System Check     | Critical file system checks    |
| 0x0C  | Registry Analysis     | Security-relevant registry keys|
| 0x0D  | Memory Protection     | Memory protection verification |
| 0x0E  | Firewall Rules        | Firewall configuration analysis|
| 0x0F  | Update Status         | System update verification     |

### Database Schema

Rex uses a relational database with the following core tables:

1. **Users & Authentication**
   - `User`: User accounts and authentication
   - `Group`: Role-based access control groups
   - `Permission`: Granular permission definitions

2. **Target Management**
   - `Target`: Systems under security assessment
   - `TargetGroup`: Organizational grouping of targets
   - `TargetTag`: Flexible tagging system for targets

3. **Scanning & Results**
   - `ScanProfile`: Scan configuration templates
   - `ScanJob`: Individual scan execution records
   - `ScanResult`: Results from completed scans
   - `Vulnerability`: Identified security issues
   - `Remediation`: Tracking of fix implementation

4. **System Data**
   - `NetworkDevice`: Discovered network devices
   - `Software`: Installed software inventory
   - `Service`: Running services information
   - `User`: User accounts on target systems
   - `Process`: Running process information

5. **Network Monitoring**
   - `NetworkMonitorLog`: Log of network monitoring events
   - `NetworkTrafficStats`: Network traffic statistics
   - `NetworkAlert`: Security alerts from network monitoring

6. **Vulnerability Management**
   - `VulnerabilityCheckup`: Vulnerability scan results
   - `Vulnerability`: Individual vulnerability findings

### API Reference

Rex provides a RESTful API for integration with other security tools:

1. **Authentication Endpoints**
   - `POST /api/auth/token/`: Obtain authentication token
   - `POST /api/auth/token/refresh/`: Refresh authentication token
   - `POST /api/auth/logout/`: Invalidate authentication token

2. **Target Management**
   - `GET /api/targets/`: List all targets
   - `POST /api/targets/`: Create a new target
   - `GET /api/targets/{id}/`: Retrieve target details
   - `PUT /api/targets/{id}/`: Update target information
   - `DELETE /api/targets/{id}/`: Remove a target

3. **Scanning Operations**
   - `GET /api/scans/`: List all scans
   - `POST /api/scans/`: Initiate a new scan
   - `GET /api/scans/{id}/`: Retrieve scan details
   - `GET /api/scans/{id}/results/`: Get scan results

4. **Vulnerability Management**
   - `GET /api/vulnerabilities/`: List all vulnerabilities
   - `GET /api/vulnerabilities/{id}/`: Get vulnerability details
   - `PUT /api/vulnerabilities/{id}/status/`: Update vulnerability status
   - `GET /api/vulnerability-checkups/`: List all vulnerability checkups
   - `POST /api/vulnerability-checkups/`: Start a new vulnerability checkup
   - `GET /api/vulnerability-checkups/{id}/`: Get checkup details
   - `GET /api/vulnerability-checkups/{id}/status/`: Get checkup status

5. **Network Monitoring**
   - `GET /api/network-monitor/stats/`: Get current network monitoring statistics
   - `POST /api/network-monitor/start/`: Start network monitoring
   - `POST /api/network-monitor/stop/`: Stop network monitoring
   - `GET /api/network-alerts/`: List all network security alerts
   - `PUT /api/network-alerts/{id}/resolve/`: Resolve a network alert

## 🔒 Security Considerations

### Authentication & Authorization
- Multi-factor authentication support
- Role-based access control
- Session management and timeout controls
- Audit logging of security-relevant actions

### Data Protection
- Encryption of sensitive data at rest
- Secure communication channels (TLS)
- Data minimization principles
- Configurable data retention policies

### Operational Security
- Agent self-protection mechanisms
- Least privilege operation
- Resource usage limitations
- Tamper detection capabilities

### Deployment Recommendations
- Network segmentation for controller components
- Regular updates and security patches
- Backup and recovery procedures
- Security monitoring integration

## 💻 Development

### Project Structure

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
│   │   │   ├── scanner/    # Application templates
│   │   │   └── ...         # Various page templates
│   │   ├── static/         # Static assets (CSS, JS, images)
│   │   ├── models.py       # Database models
│   │   ├── views.py        # Main view controllers
│   │   ├── views_monitoring.py # Network monitoring views
│   │   ├── views_port_scanner.py # Port scanning views
│   │   ├── views_software_vuln_scanner.py # Vulnerability scanning views
│   │   ├── urls.py         # Application URL routing
│   │   ├── network_monitor.py # Network monitoring functionality
│   │   ├── software_vulnerability_scanner.py # Vulnerability scanning logic
│   │   └── ...             # Other application files
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
│   │   ├── vulnerability_scanner.py # Vulnerability scanning functionality
│   │   └── static/         # Static files for agent HTTP server
│   └── run.md              # Instructions for running agent and host
├── docs/                   # Documentation
│   └── images/             # Documentation images
├── scanner/                # Additional scanner functionality
│   └── vulnerability_db/   # Vulnerability database files
├── build_agent_exe.py      # Script to build agent executable
├── build_agent.bat         # Batch file to run build script on Windows
├── agent_listener.exe      # Compiled agent executable (after build)
├── AGENT_README.md         # Documentation for agent executable
├── docker-compose.yml      # Docker configuration for production
├── .env.example            # Example environment variables
└── README.md               # Project overview and documentation
```

### Contributing Guidelines

1. **Code Style**
   - Follow PEP 8 guidelines for Python code
   - Use consistent naming conventions
   - Include docstrings for all functions and classes
   - Maintain test coverage for new features

2. **Development Workflow**
   - Fork the repository
   - Create feature branches from `develop`
   - Submit pull requests for review
   - Ensure CI/CD pipeline passes

3. **Issue Reporting**
   - Use the issue tracker for bugs and feature requests
   - Include detailed reproduction steps for bugs
   - Tag issues appropriately

### Testing

1. **Running Tests**
   ```bash
   # Run all tests
   python -m pytest

   # Run specific test category
   python -m pytest tests/unit/

   # Run with coverage report
   python -m pytest --cov=.
   ```

2. **Test Categories**
   - Unit tests for individual components
   - Integration tests for component interaction
   - End-to-end tests for complete workflows
   - Performance tests for resource usage

## 🔜 Roadmap

### Short-term (Next 3 Months)
- [x] User interface improvements
- [x] Enhanced reporting capabilities
- [ ] Additional vulnerability detection modules
- [ ] Performance optimizations for large networks

### Medium-term (3-6 Months)
- [ ] End-to-end encryption for all communications
- [ ] Advanced authentication system
- [ ] Cross-platform agent support
- [ ] Integration with popular SIEM solutions

### Long-term (6-12 Months)
- [ ] Machine learning for anomaly detection
- [ ] Automated remediation capabilities
- [ ] Cloud environment assessment
- [ ] Container security scanning
- [ ] Mobile device security assessment

## 🔧 Troubleshooting

### Common Issues

1. **Agent Connection Problems**
   - Verify network connectivity
   - Check firewall rules for port 23033
   - Ensure agent service is running
   - Validate controller address configuration

2. **Dashboard Access Issues**
   - Confirm web server is running
   - Verify database connection
   - Check authentication credentials
   - Review server logs for errors

3. **Scan Failures**
   - Ensure target system is accessible
   - Verify agent has necessary permissions
   - Check for antivirus/security software blocking scans
   - Review scan timeout settings for complex scans

4. **Agent Executable Issues**
   - If the agent executable fails to start, check for missing dependencies
   - Some antivirus software may flag the executable; add an exception
   - Ensure the executable has appropriate permissions
   - Try running as administrator if access issues occur
   - If the executable crashes, check the logs for error messages

### Diagnostic Steps

1. **Checking Agent Status**
   ```bash
   # Check if agent is running
   netstat -ano | findstr 23033

   # View agent logs
   # Logs are printed to console when running the executable
   ```

2. **Testing Dashboard-Agent Communication**
   ```bash
   # From the dashboard server
   telnet <agent-ip> 23033

   # Or use the test connection utility
   python -m proto.host.host_controller --target <agent-ip> --command 1
   ```

3. **Debugging the Agent Executable**
   - Run the executable from command prompt to see console output
   - Look for error messages during startup
   - Verify all required files are present in the executable directory
   - Verify agent has sufficient permissions
   - Check for resource constraints
   - Review scan logs for specific errors

### Support Resources

- **Documentation**: Comprehensive guides at `/docs`
- **Issue Tracker**: Report bugs on GitHub
- **Community Forum**: Discuss with other users at [community.rexsecurity.com](https://community.rexsecurity.com)
- **Email Support**: For premium users at support@rexsecurity.com

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👏 Acknowledgements

- [Django](https://www.djangoproject.com/) - The web framework used
- [Chart.js](https://www.chartjs.org/) - Interactive visualization library
- [Bootstrap](https://getbootstrap.com/) - Frontend component library
- [Font Awesome](https://fontawesome.com/) - Icon set
- [Scapy](https://scapy.net/) - Packet manipulation library
- [PyInstaller](https://pyinstaller.org/) - Used for creating standalone executables
- [WMI](https://pypi.org/project/WMI/) - Windows Management Instrumentation for Python
- [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/) - MAC address vendor lookup
- All contributors who have helped improve ShadowPulse Scanner
