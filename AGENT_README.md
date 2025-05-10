# Agent Listener Executable

This directory contains tools to build a standalone executable for the agent listener component of the ShadowPulse Scanner.

## Building the Executable

### Prerequisites

- Python 3.8 or higher
- Internet connection (to download required packages)

### Build Instructions

1. Run the build script:
   - On Windows: Double-click `build_agent.bat` or run it from the command line
   - On Linux/macOS: Run `python build_agent_exe.py`

2. The script will:
   - Check for and install required packages (PyInstaller, scapy, mac_vendor_lookup, wmi)
   - Create a temporary entry point script
   - Build the executable using PyInstaller
   - Copy the executable to the current directory

3. After a successful build, you'll find `agent_listener.exe` (Windows) or `agent_listener` (Linux/macOS) in the current directory.

## Using the Executable

### Running the Agent Listener

1. Simply double-click the executable or run it from the command line:
   ```
   agent_listener.exe
   ```

2. The agent will start and listen on port 23033 by default.

3. You should see output similar to:
   ```
   [+] Agent listening on 0.0.0.0:23033
   [+] Ready to accept connections
   [HTTP] Server started on http://0.0.0.0:23033
   ```

### Connecting to the Agent

- From the dashboard, add the agent's IP address as a target
- The dashboard will automatically connect to the agent on port 23033

### Troubleshooting

- **Firewall Issues**: Make sure port 23033 is open in your firewall
- **Permission Issues**: On Windows, you might need to run the executable as Administrator
- **Antivirus Blocking**: Some antivirus software might block the executable; add an exception if needed

## Security Considerations

- The agent listener provides remote access to system information
- Only run the agent on systems you control and trust
- Consider network segmentation to limit access to the agent
- The agent does not implement authentication by default; use network security measures to restrict access

## Customizing the Agent

If you need to customize the agent (e.g., change the default port), you'll need to modify the source code and rebuild the executable:

1. Modify the relevant files in the `proto/agent` directory
2. Run the build script again to create a new executable

## License

This software is subject to the same license as the main ShadowPulse Scanner project.
