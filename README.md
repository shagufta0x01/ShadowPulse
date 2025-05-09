# 🔍 ShadowPulse Scanner (ZAMBOT)

<div align="center">
  <img src="docs/images/rex-logo.png" alt="ShadowPulse Scanner Logo" width="180" height="180">
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

#### Agent Deployment

1. **Build the agent package**
   ```bash
   cd agent
   python setup.py build
   ```

2. **Deploy to target systems**
   - Copy the built package to the target system
   - Install with administrative privileges
   - Configure the agent to connect to your controller

3. **Verify agent connectivity**
   - From the dashboard, navigate to Target Management
   - Confirm the agent appears as "Connected"

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

The Rex Security dashboard provides a comprehensive view of your security posture:

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

### Agent-Controller Protocol

The system uses a custom binary protocol (ZAMBOT) for efficient and reliable communication between the controller and agents:

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
rex-security/
├── agent/                  # Agent component
│   ├── modules/            # Security assessment modules
│   ├── core/               # Core agent functionality
│   └── utils/              # Utility functions
├── dashboard/              # Web dashboard
│   ├── scanner/            # Main application
│   │   ├── templates/      # HTML templates
│   │   ├── static/         # Static assets
│   │   ├── models.py       # Data models
│   │   ├── views.py        # View controllers
│   │   └── urls.py         # URL routing
│   └── dashboard/          # Project settings
├── proto/                  # Protocol definitions
│   ├── host/               # Controller-side protocol
│   └── agent/              # Agent-side protocol
├── docs/                   # Documentation
│   ├── images/             # Documentation images
│   ├── api/                # API documentation
│   └── user-guide/         # User guides
├── tests/                  # Test suite
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── requirements.txt        # Python dependencies
├── setup.py                # Installation script
└── README.md               # Project overview
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
- All contributors who have helped improve Rex Security Scanner

