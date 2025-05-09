"""
Test script to verify connection to the agent and run a vulnerability scan.
"""

import os
import sys
import json

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    # Import the host controller module
    from proto.host.host_controller import send_command
    from proto.pro.protocol import CMD_VULNERABILITY_SCAN
    
    print("Successfully imported modules")
    
    # Agent IP address
    agent_ip = "192.168.29.244"  # Replace with your agent IP
    
    print(f"Connecting to agent at {agent_ip}...")
    
    # Send a vulnerability scan command
    response = send_command(agent_ip, CMD_VULNERABILITY_SCAN, "quick", verbose=True)
    
    if response:
        print("Received response from agent")
        
        # Try to parse the JSON response
        try:
            result = json.loads(response)
            print(f"Successfully parsed JSON response")
            print(f"Scan status: {result.get('status')}")
            print(f"Total vulnerabilities: {result.get('total_vulnerabilities')}")
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON response: {str(e)}")
            print(f"Response preview: {response[:200]}...")
    else:
        print("No response received from agent")
        
except ImportError as e:
    print(f"Error importing modules: {str(e)}")
except Exception as e:
    print(f"Error: {str(e)}")
