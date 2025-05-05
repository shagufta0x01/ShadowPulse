# 🔍 ShadowPulse Scanner

A powerful and versatile system vulnerability assessment tool that provides comprehensive security analysis through an efficient client-server architecture.

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/yourusername/zambot-scanner)

</div>

## ✨ Key Features

- 🛡️ **Comprehensive Security Analysis**
  - AMSI Provider Detection
  - Antivirus Analysis
  - Security Audit Policies
  - UAC Settings Verification
  - System Certificates Analysis

- 🔍 **System Intelligence**
  - OS Information Collection
  - Software Inventory
  - Environment Analysis
  - User & Group Enumeration
  - PowerShell History Analysis

- 🌐 **Network Reconnaissance**
  - ARP Scanning
  - Service Discovery
  - Port Analysis
  - DNS Cache Inspection
  - Network Share Mapping

## 🏗️ Architecture

### Agent Component
The agent operates on target systems as a TCP server (port 23033):
- 📦 Deployable as standalone executable
- 🔄 Real-time system monitoring
- 🛠️ Modular security assessment engine
- 📊 Efficient data collection

### Controller Component
Manages assessment operations across multiple targets:
- 🎮 Centralized command interface
- 📡 Multi-target management
- 📊 Real-time data processing
- 🗂️ Result aggregation

## 🔌 Protocol Specification

### Packet Structure

**Request Format (Host → Agent)**
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

**Response Format (Agent → Host)**
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

## 🚀 Quick Start

1. **Setup Agent**
```bash
python -m agent.agent_listener
```

2. **Launch Controller**
```bash
python -m host.host_controller
```

## 🛠️ Command Reference

| Code  | Operation              | Description                    |
|-------|------------------------|--------------------------------|
| 0x01  | Basic OS Info         | Core system information        |
| 0x02  | Software Inventory    | Installed products scan        |
| 0x03  | Network Scan          | Network reconnaissance         |
| 0x04  | System Diagnostics    | System health check            |
| 0x05  | Full OS Info         | Detailed system analysis       |
| 0x06  | Network Details      | Comprehensive network data     |
| 0x07  | PowerShell Analysis  | Command history & settings     |

## 🔒 Security Notes

- Requires elevated privileges for complete system analysis
- Currently uses unencrypted communication (development only)
- Implement proper authentication for production use
- Use caution with network scanning features

## 🔜 Roadmap

- [ ] End-to-end encryption
- [ ] Authentication system
- [ ] Cross-platform support
- [ ] Advanced reporting engine
- [ ] Remote command execution
- [ ] Custom module support

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.



