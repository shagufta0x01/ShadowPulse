import socket
import struct
import argparse
import sys
from pro.protocol import *
from host.utils import build_request_header

def parse_header(data):
    return struct.unpack(">6s B B I B I H", data)

def send_request(cmd_code, target_ip='127.0.0.1', target_port=23033, payload=b''):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # Set a timeout for connection attempts
        s.connect((target_ip, target_port))

        req_id = 1
        header = build_request_header(0x01, req_id, cmd_code, len(payload))
        s.sendall(header + payload)

        # Receive response header
        response_header = s.recv(HEADER_SIZE)
        # Parse header but only use status_code and payload_len
        _, _, _, _, status_code, payload_len, _ = parse_header(response_header)

        # For large data responses, receive and print data in chunks for better responsiveness
        if payload_len > 4096:
            print(f"\n[Response status={status_code}]")
            received_data = b""
            chunk_size = 4096  # Receive in 4KB chunks

            while len(received_data) < payload_len:
                chunk = s.recv(min(chunk_size, payload_len - len(received_data)))
                if not chunk:
                    break
                received_data += chunk
                # Print the chunk as it's received
                try:
                    print(chunk.decode(), end='', flush=True)
                except UnicodeDecodeError:
                    pass

            result = received_data
        else:
            # For other commands, receive all at once
            response_payload = s.recv(payload_len)
            print(f"\n[Response status={status_code}]\n{response_payload.decode()}")
            result = response_payload

        s.close()
        return result

    except socket.timeout:
        print(f"\nError: Connection to {target_ip}:{target_port} timed out")
        return None
    except ConnectionRefusedError:
        print(f"\nError: Connection to {target_ip}:{target_port} refused. Make sure the agent is running.")
        return None
    except Exception as e:
        print(f"\nError: {str(e)}")
        return None

def get_command_name(cmd_code):
    """Get the command name from the command code"""
    for name, value in globals().items():
        if name.startswith('CMD_') and value == cmd_code:
            return name.replace('CMD_', '').replace('_', ' ').title()
    return f"Command {cmd_code}"

def list_available_commands():
    """List all available commands"""
    print("\nAvailable Commands:")
    print("-" * 50)

    # Group commands by category
    os_commands = []
    network_commands = []
    basic_commands = []

    for name, value in globals().items():
        if name.startswith('CMD_'):
            cmd_name = name.replace('CMD_', '').replace('_', ' ').title()
            cmd_code = value

            if 0x10 <= cmd_code <= 0x2F:  # OS Info commands
                os_commands.append((cmd_name, cmd_code))
            elif 0x30 <= cmd_code <= 0x4F:  # Network Info commands
                network_commands.append((cmd_name, cmd_code))
            else:  # Basic commands
                basic_commands.append((cmd_name, cmd_code))

    # Print basic commands
    print("\nBasic Commands:")
    for cmd_name, cmd_code in sorted(basic_commands, key=lambda x: x[1]):
        print(f"  {cmd_code:02X}: {cmd_name}")

    # Print OS Info commands
    print("\nOS Info Commands:")
    for cmd_name, cmd_code in sorted(os_commands, key=lambda x: x[1]):
        print(f"  {cmd_code:02X}: {cmd_name}")

    # Print Network Info commands
    print("\nNetwork Info Commands:")
    for cmd_name, cmd_code in sorted(network_commands, key=lambda x: x[1]):
        print(f"  {cmd_code:02X}: {cmd_name}")

def run_command(args):
    """Run a specific command"""
    if args.list_commands:
        list_available_commands()
        return

    if args.command is None:
        print("Error: No command specified. Use --list-commands to see available commands.")
        return

    cmd_code = args.command
    target_ip = args.target
    target_port = args.port

    print(f"\n=== Running {get_command_name(cmd_code)} ===")
    print(f"Target: {target_ip}:{target_port}")

    # For network commands that need an IP to scan
    if cmd_code in [CMD_PORT_SCANNER, CMD_BANNER_GRABBER, CMD_FULL_NETWORK_INFO]:
        scan_ip = args.scan_ip if args.scan_ip else target_ip
        payload = scan_ip.encode()
        print(f"Scanning IP: {scan_ip}")
        send_request(cmd_code, target_ip, target_port, payload)
    else:
        send_request(cmd_code, target_ip, target_port)

def run_all_commands(args):
    """Run all basic commands"""
    target_ip = args.target
    target_port = args.port

    basic_commands = [
        (CMD_OS_INFO, "Basic OS Info"),
        (CMD_GET_POWERSHELL_HISTORY, "PowerShell History"),
        (CMD_LIST_PRODUCTS, "Installed Products"),
        (CMD_SYSTEM_DIAG, "System Diagnostic")
    ]

    for cmd_code, cmd_name in basic_commands:
        print(f"\n=== {cmd_name} ===")
        print(f"Target: {target_ip}:{target_port}")
        send_request(cmd_code, target_ip, target_port)

    # Run full reports last as they take longer
    print("\n=== Full OS Report ===")
    print(f"Target: {target_ip}:{target_port}")
    send_request(CMD_FULL_OS_INFO, target_ip, target_port)

    scan_ip = args.scan_ip if args.scan_ip else target_ip
    print("\n=== Full Network Report ===")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Scanning IP: {scan_ip}")
    send_request(CMD_FULL_NETWORK_INFO, target_ip, target_port, scan_ip.encode())

def main():
    parser = argparse.ArgumentParser(description='System Vulnerability Assessment Tool - Host Controller')
    parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address (default: 127.0.0.1)')
    parser.add_argument('--port', '-p', type=int, default=23033, help='Target port (default: 23033)')
    parser.add_argument('--scan-ip', '-s', help='IP address to scan for network commands (default: same as target)')
    parser.add_argument('--command', '-c', type=lambda x: int(x, 0), help='Command code to run (e.g. 0x01 or 1)')
    parser.add_argument('--list-commands', '-l', action='store_true', help='List all available commands')
    parser.add_argument('--all', '-a', action='store_true', help='Run all basic commands')

    args = parser.parse_args()

    # If no specific arguments are provided, run all basic commands
    if len(sys.argv) == 1:
        print("Running in default mode - executing all basic commands")
        args.all = True
        run_all_commands(args)
    elif args.all:
        run_all_commands(args)
    else:
        run_command(args)

if __name__ == "__main__":
    main()

