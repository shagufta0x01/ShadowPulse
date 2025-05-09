"""
Test script to verify connection to the agent and run a vulnerability scan.
"""

import os
import sys
import json
import socket
import time

print(f"Current working directory: {os.getcwd()}")
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")

# Add the parent directory to the Python path
parent_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
print(f"Adding to path: {parent_dir}")
sys.path.insert(0, parent_dir)

# Also add the current directory to the path
current_dir = os.getcwd()
print(f"Adding current directory to path: {current_dir}")
sys.path.insert(0, current_dir)

# First, let's try a simple socket connection to verify the agent is reachable
agent_ip = "192.168.29.244"  # Replace with your agent IP
agent_port = 23033

print(f"\nTesting basic socket connection to {agent_ip}:{agent_port}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    result = s.connect_ex((agent_ip, agent_port))
    if result == 0:
        print(f"Socket connection successful!")
        s.close()
    else:
        print(f"Socket connection failed with error code: {result}")
        print("Please check if the agent is running and the IP address is correct.")
        sys.exit(1)
except Exception as e:
    print(f"Socket connection error: {str(e)}")
    sys.exit(1)

# Now try to import the modules and send a command
try:
    print("\nImporting modules...")

    # Try a direct import approach
    print("Trying direct import...")
    import sys
    import importlib.util

    # Import host_controller.py
    host_controller_path = os.path.join(current_dir, "proto", "host", "host_controller.py")
    print(f"Loading host_controller from: {host_controller_path}")

    if os.path.exists(host_controller_path):
        spec = importlib.util.spec_from_file_location("host_controller", host_controller_path)
        host_controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host_controller)
        send_command = host_controller.send_command
        print("Successfully imported send_command function")
    else:
        print(f"Error: {host_controller_path} does not exist")
        sys.exit(1)

    # Import protocol.py
    protocol_path = os.path.join(current_dir, "proto", "pro", "protocol.py")
    print(f"Loading protocol from: {protocol_path}")

    if os.path.exists(protocol_path):
        spec = importlib.util.spec_from_file_location("protocol", protocol_path)
        protocol = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(protocol)
        CMD_VULNERABILITY_SCAN = protocol.CMD_VULNERABILITY_SCAN
        CMD_OS_INFO = protocol.CMD_OS_INFO
        print("Successfully imported protocol constants")
        print(f"CMD_VULNERABILITY_SCAN = {CMD_VULNERABILITY_SCAN} (0x{CMD_VULNERABILITY_SCAN:02X})")
        print(f"CMD_OS_INFO = {CMD_OS_INFO} (0x{CMD_OS_INFO:02X})")
    else:
        print(f"Error: {protocol_path} does not exist")
        sys.exit(1)

    print(f"\nConnecting to agent at {agent_ip}...")

    # Send a simple command first (OS info)
    print("Sending OS info command first...")
    try:
        print(f"Sending CMD_OS_INFO (0x{CMD_OS_INFO:02X})...")
        os_info_response = send_command(agent_ip, CMD_OS_INFO, "", verbose=True)
        if os_info_response:
            print("OS info command successful!")
            print(f"Response preview: {os_info_response[:100]}...")
        else:
            print("OS info command failed!")
    except Exception as e:
        print(f"Error sending OS info command: {str(e)}")

    # Wait a bit before sending the next command
    print("Waiting 2 seconds before sending vulnerability scan command...")
    time.sleep(2)

    # Send a vulnerability scan command
    print("\nSending vulnerability scan command...")
    try:
        print(f"Sending CMD_VULNERABILITY_SCAN (0x{CMD_VULNERABILITY_SCAN:02X}) with payload 'quick'...")
        response = send_command(agent_ip, CMD_VULNERABILITY_SCAN, "quick", verbose=True)

        if response:
            print("\nReceived response from agent")
            print(f"Response type: {type(response)}")
            print(f"Response length: {len(response) if response else 0}")

            # Try to parse the JSON response
            try:
                # If response is bytes, decode it first
                if isinstance(response, bytes):
                    response_str = response.decode('utf-8', errors='replace')
                else:
                    response_str = response

                print(f"Response preview: {response_str[:200]}...")

                result = json.loads(response_str)
                print(f"Successfully parsed JSON response")
                print(f"Scan status: {result.get('status')}")
                print(f"Total vulnerabilities: {result.get('total_vulnerabilities')}")

                # Print the first few vulnerabilities
                vulnerabilities = result.get('vulnerabilities', [])
                print(f"First few vulnerabilities:")
                for i, vuln in enumerate(vulnerabilities[:3]):
                    print(f"  {i+1}. {vuln.get('title')} - {vuln.get('severity')}")

            except json.JSONDecodeError as e:
                print(f"Error parsing JSON response: {str(e)}")
                print(f"Response preview: {response_str[:200]}...")
        else:
            print("No response received from agent")
    except Exception as e:
        print(f"Error sending vulnerability scan command: {str(e)}")

except ImportError as e:
    print(f"Error importing modules: {str(e)}")
except Exception as e:
    print(f"Error: {str(e)}")
