import socket
import struct
import threading
import time
import zlib
import io
from agent.handlers import command_dispatcher
from pro.protocol import HEADER_SIZE, HEADER_FORMAT, MAGIC_HEADER, CMD_SYSTEM_DIAG, CMD_FULL_OS_INFO, CMD_FULL_NETWORK_INFO, CMD_GET_OS_INFO_SECTION, FLAG_COMPRESSED

def handle_client(conn, addr):
    """Handle client connection with improved error handling and timeouts"""
    print(f"[+] Handling connection from {addr}")
    try:
        # Set a timeout for receiving the header
        conn.settimeout(30)

        header = conn.recv(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            print(f"[!] Invalid header length from {addr}")
            return

        magic, version, flags, req_id, cmd_code, payload_len, reserved = struct.unpack(HEADER_FORMAT, header)
        if magic != MAGIC_HEADER:
            print(f"[!] Invalid magic header from {addr}")
            return

        # Receive payload if any
        payload = b""
        if payload_len > 0:
            payload = conn.recv(payload_len)
            if len(payload) < payload_len:
                print(f"[!] Incomplete payload from {addr}: got {len(payload)} of {payload_len} bytes")

        # Determine if this is a complex command that might take longer
        is_complex_command = cmd_code in [CMD_SYSTEM_DIAG, CMD_FULL_OS_INFO, CMD_FULL_NETWORK_INFO, CMD_GET_OS_INFO_SECTION]

        # Log command information
        command_name = "Unknown Command"
        for name, value in globals().items():
            if name.startswith('CMD_') and value == cmd_code:
                command_name = name

        print(f"[+] Received command {command_name} (0x{cmd_code:02x}) from {addr}")
        if is_complex_command:
            print(f"[+] This is a complex command that may take longer to process")

        # Run handler with appropriate timeout handling
        try:
            # For complex commands, we'll send periodic keepalive messages to the client
            if is_complex_command:
                print(f"[+] Starting complex command execution for {addr}")

            # Get the payload as string if present
            payload_str = payload.decode().strip() if payload else ""

            # Execute the command
            start_time = time.time()
            response_data = command_dispatcher(cmd_code, ip=payload_str)
            execution_time = time.time() - start_time

            print(f"[+] Command {command_name} completed in {execution_time:.2f} seconds")
            status = 0
        except Exception as e:
            print(f"[!] Handler error for {addr}: {e}")
            response_data = f"Error executing command: {str(e)}".encode()
            status = 1

        # Check if this is a very large HTML response that might cause issues
        is_html = response_data.startswith(b'<!DOCTYPE html>') or response_data.startswith(b'<html>')
        is_very_large = len(response_data) > 50000  # 50KB threshold

        # For very large HTML responses, we'll add a note about potential issues
        if is_html and is_very_large:
            # Add a warning message to the HTML
            warning_message = b"""
            <div class="alert alert-info" style="margin: 20px 0; padding: 15px; border-left: 5px solid #2196F3; background-color: #E3F2FD; color: #0D47A1;">
                <strong>Note:</strong> This is a large report. If you experience any issues viewing it,
                try running individual commands for specific information categories instead of the full report.
            </div>
            """

            # Insert the warning at the beginning of the body
            response_data = response_data.replace(b'<body>', b'<body>' + warning_message)

        # Determine if we should compress the response
        # Compress large responses (> 10KB) or HTML content
        should_compress = len(response_data) > 10240 or is_html

        if should_compress:
            # Compress the response data
            print(f"[+] Compressing response data ({len(response_data)} bytes)")
            compressed_data = zlib.compress(response_data, level=9)  # Maximum compression
            compression_ratio = (1 - len(compressed_data) / len(response_data)) * 100
            print(f"[+] Compressed to {len(compressed_data)} bytes ({compression_ratio:.1f}% reduction)")

            # Use the compressed data and set the compression flag
            response_payload = compressed_data
            flags |= FLAG_COMPRESSED
        else:
            # Use the original data
            response_payload = response_data

        # Build response header
        resp_header = struct.pack(
            HEADER_FORMAT,
            MAGIC_HEADER,
            version,
            flags,
            req_id,
            status,
            len(response_payload),
            reserved
        )

        # Send response with robust error handling and retries
        try:
            # Configure socket for better reliability
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            # On Windows, we can set TCP keepalive parameters
            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                # Set keepalive parameters (enable, idle time in ms, interval in ms)
                conn.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))

            # Set a longer timeout for sending data
            conn.settimeout(180)  # 3 minutes timeout for sending

            # First send the header with retry
            max_retries = 3
            for retry in range(max_retries):
                try:
                    conn.sendall(resp_header)
                    break
                except Exception as e:
                    if retry < max_retries - 1:
                        print(f"[!] Error sending header, retrying ({retry+1}/{max_retries}): {e}")
                        time.sleep(1)
                    else:
                        raise

            # Then send the payload in smaller chunks with retry logic
            chunk_size = 4096  # 4KB chunks (smaller for better reliability)
            total_sent = 0
            data_len = len(response_payload)

            print(f"[+] Sending {data_len} bytes of response data to {addr}")

            # Send data in chunks with retry logic
            while total_sent < data_len:
                chunk = response_payload[total_sent:total_sent + chunk_size]

                # Try to send this chunk with retries
                for retry in range(max_retries):
                    try:
                        bytes_sent = conn.send(chunk)
                        if bytes_sent == 0:
                            raise RuntimeError("Socket connection broken")

                        total_sent += bytes_sent

                        # If we sent less than the full chunk, adjust the next chunk
                        if bytes_sent < len(chunk):
                            chunk = chunk[bytes_sent:]
                            continue

                        break  # Successfully sent the chunk
                    except Exception as e:
                        if retry < max_retries - 1:
                            print(f"[!] Error sending chunk at position {total_sent}, retrying ({retry+1}/{max_retries}): {e}")
                            time.sleep(1)
                        else:
                            raise

                # Log progress for large responses
                if data_len > 10000 and total_sent % 10000 < chunk_size:
                    progress = (total_sent / data_len) * 100
                    print(f"[+] Sent {total_sent} of {data_len} bytes ({progress:.1f}%)")

                # Add small delay between chunks to prevent overwhelming the receiver
                if data_len > 10000:
                    time.sleep(0.01)

            print(f"[+] Response sent successfully to {addr}")

        except Exception as e:
            print(f"[!] Error sending response to {addr}: {e}")

    except Exception as e:
        print(f"[!] Connection error with {addr}: {e}")

    finally:
        try:
            conn.close()
            print(f"[+] Connection with {addr} closed")
        except:
            pass

def start_server(host="0.0.0.0", port=23033):
    """Start the agent server with improved connection handling"""
    # Create a socket with keep-alive enabled
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind and listen
    server.bind((host, port))
    server.listen(10)  # Increased backlog for multiple connections

    print(f"[+] Agent listening on {host}:{port}")
    print(f"[+] Ready to accept connections")

    while True:
        try:
            conn, addr = server.accept()
            print(f"[+] New connection from {addr}")

            # Handle each client in a separate thread
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

        except Exception as e:
            print(f"[!] Error accepting connection: {e}")
            # Brief pause to avoid CPU spinning on repeated errors
            time.sleep(1)

if __name__ == "__main__":
    start_server()
