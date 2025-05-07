import socket
import struct
import threading
import time
import zlib
import io
from proto.agent.handlers import command_dispatcher
from proto.pro.protocol import *

def handle_client(conn, addr):
    """Handle client connection with improved error handling and timeouts"""
    print(f"[+] Handling connection from {addr}")
    try:
        # Configure socket for better reliability
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # On Windows, set TCP keepalive parameters
        if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
            # Set keepalive parameters (enable, idle time in ms, interval in ms)
            conn.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))

        # Set a timeout for receiving the header
        conn.settimeout(60)  # Increased timeout for better reliability

        # Receive header with retry logic
        header = b""
        remaining = HEADER_SIZE
        max_retries = 3
        retry_count = 0

        while remaining > 0:
            try:
                chunk = conn.recv(remaining)
                if not chunk:
                    if retry_count < max_retries:
                        retry_count += 1
                        print(f"[!] Empty chunk received, retrying ({retry_count}/{max_retries})")
                        time.sleep(1)
                        continue
                    else:
                        print(f"[!] Connection closed while receiving header from {addr}")
                        return

                header += chunk
                remaining -= len(chunk)
                retry_count = 0  # Reset retry count on successful receive

            except socket.timeout:
                if retry_count < max_retries:
                    retry_count += 1
                    print(f"[!] Timeout receiving header, retrying ({retry_count}/{max_retries})")
                    time.sleep(1)
                else:
                    print(f"[!] Timeout receiving header from {addr} after {max_retries} retries")
                    return

        if len(header) < HEADER_SIZE:
            print(f"[!] Invalid header length from {addr}: got {len(header)} of {HEADER_SIZE} bytes")
            return

        try:
            magic, version, flags, req_id, cmd_code, payload_len, reserved = struct.unpack(HEADER_FORMAT, header)
        except struct.error as e:
            print(f"[!] Error unpacking header from {addr}: {e}")
            return

        if magic != MAGIC_HEADER:
            print(f"[!] Invalid magic header from {addr}")
            return

        # Receive payload if any
        payload = b""
        if payload_len > 0:
            remaining = payload_len
            retry_count = 0

            while remaining > 0:
                try:
                    chunk = conn.recv(min(4096, remaining))  # Receive in smaller chunks
                    if not chunk:
                        if retry_count < max_retries:
                            retry_count += 1
                            print(f"[!] Empty chunk received for payload, retrying ({retry_count}/{max_retries})")
                            time.sleep(1)
                            continue
                        else:
                            print(f"[!] Connection closed while receiving payload from {addr}")
                            break

                    payload += chunk
                    remaining -= len(chunk)
                    retry_count = 0  # Reset retry count on successful receive

                except socket.timeout:
                    if retry_count < max_retries:
                        retry_count += 1
                        print(f"[!] Timeout receiving payload, retrying ({retry_count}/{max_retries})")
                        time.sleep(1)
                    else:
                        print(f"[!] Timeout receiving payload from {addr} after {max_retries} retries")
                        break

            if len(payload) < payload_len:
                print(f"[!] Incomplete payload from {addr}: got {len(payload)} of {payload_len} bytes")

        # Determine if this is a complex command that might take longer
        is_complex_command = cmd_code in [CMD_SYSTEM_DIAG, CMD_FULL_OS_INFO, CMD_FULL_NETWORK_INFO, CMD_GET_OS_INFO_SECTION, CMD_GET_RUNNING_PROCESSES, CMD_ANALYZE_PROCESS_MEMORY]

        # Log command information
        command_name = "Unknown Command"
        for name, value in globals().items():
            if name.startswith('CMD_') and value == cmd_code:
                command_name = name

        # Print more detailed command information
        print(f"[+] Received command {command_name} (0x{cmd_code:02x}, decimal: {cmd_code}) from {addr}")
        print(f"[+] Command code type: {type(cmd_code)}, value: {cmd_code}")
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
            # Socket should already be configured for reliability in the beginning of handle_client

            # Set an even longer timeout for sending data
            conn.settimeout(300)  # 5 minutes timeout for sending large responses

            # First send the header with retry
            max_retries = 5  # Increased retries for better reliability
            header_sent = False

            for retry in range(max_retries):
                try:
                    conn.sendall(resp_header)
                    header_sent = True
                    break
                except (socket.timeout, ConnectionResetError) as e:
                    if retry < max_retries - 1:
                        print(f"[!] Error sending header, retrying ({retry+1}/{max_retries}): {e}")
                        time.sleep(2)  # Longer delay between retries
                    else:
                        print(f"[!] Failed to send header after {max_retries} attempts: {e}")
                        raise
                except Exception as e:
                    print(f"[!] Unexpected error sending header: {e}")
                    raise

            if not header_sent:
                print(f"[!] Could not send header to {addr}, aborting response")
                return

            # Then send the payload in smaller chunks with retry logic
            chunk_size = 2048  # Smaller chunks (2KB) for better reliability
            total_sent = 0
            data_len = len(response_payload)

            print(f"[+] Sending {data_len} bytes of response data to {addr}")

            # For very large responses, add a progress indicator
            progress_interval = max(1024, data_len // 20)  # Show progress at 5% intervals
            last_progress_report = 0

            # Send data in chunks with retry logic
            while total_sent < data_len:
                # Calculate the current chunk to send
                end_pos = min(total_sent + chunk_size, data_len)
                chunk = response_payload[total_sent:end_pos]
                chunk_retries = 0
                chunk_sent = False

                # Try to send this chunk with retries
                while chunk_retries < max_retries and not chunk_sent:
                    try:
                        bytes_sent = conn.send(chunk)
                        if bytes_sent == 0:
                            raise RuntimeError("Socket connection broken")

                        total_sent += bytes_sent

                        # If we sent less than the full chunk, adjust the next chunk
                        if bytes_sent < len(chunk):
                            chunk = chunk[bytes_sent:]
                        else:
                            chunk_sent = True

                    except (socket.timeout, ConnectionResetError, socket.error) as e:
                        # Check for specific Windows socket errors
                        is_win_error = hasattr(e, 'winerror') and e.winerror in [10053, 10054, 10057, 10058]

                        chunk_retries += 1
                        if chunk_retries < max_retries:
                            # For Windows error 10053 (connection aborted by software), use longer delay
                            if is_win_error and e.winerror == 10053:
                                delay = 5  # Longer delay for software-caused aborts
                                print(f"[!] Connection aborted by software, waiting {delay}s before retry ({chunk_retries}/{max_retries})")
                            else:
                                delay = 2
                                print(f"[!] Error sending chunk at position {total_sent}, retrying ({chunk_retries}/{max_retries}): {e}")

                            time.sleep(delay)

                            # For Windows error 10053, try to reconnect if possible
                            if is_win_error and e.winerror == 10053 and chunk_retries >= 3:
                                print(f"[!] Multiple software aborts detected, connection may be blocked")
                                # We can't really reconnect here as we're in the middle of a response
                                # Just inform the user that this might be a security software issue
                                print(f"[!] This may be caused by security software (antivirus, firewall) blocking the connection")
                                print(f"[!] Consider adding an exception for this application in your security software")
                        else:
                            print(f"[!] Failed to send chunk after {max_retries} attempts: {e}")
                            # For Windows error 10053, provide more helpful message
                            if is_win_error and e.winerror == 10053:
                                print(f"[!] Connection repeatedly aborted by software on the host machine")
                                print(f"[!] This is likely caused by security software blocking the connection")
                                print(f"[!] Try adding an exception for this application in your security software")
                            raise
                    except Exception as e:
                        print(f"[!] Unexpected error sending chunk: {e}")
                        # Try to provide more context for the error
                        print(f"[!] Error type: {type(e).__name__}, Error args: {e.args}")
                        raise

                # Log progress for large responses at regular intervals
                if total_sent - last_progress_report >= progress_interval:
                    progress = (total_sent / data_len) * 100
                    print(f"[+] Sent {total_sent} of {data_len} bytes ({progress:.1f}%)")
                    last_progress_report = total_sent

                # Add small delay between chunks to prevent overwhelming the receiver
                # Adjust delay based on data size - larger data gets longer delays
                if data_len > 100000:  # Very large response (>100KB)
                    time.sleep(0.05)
                elif data_len > 10000:  # Large response (>10KB)
                    time.sleep(0.02)

            print(f"[+] Response sent successfully to {addr} ({data_len} bytes)")

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
    server = None
    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Set socket timeout
            server.settimeout(60)

            # Bind and listen
            server.bind((host, port))
            server.listen(20)  # Increased backlog for multiple connections

            print(f"[+] Agent listening on {host}:{port}")
            print(f"[+] Ready to accept connections")

            # Reset retry count on successful binding
            retry_count = 0
            break

        except socket.error as e:
            retry_count += 1
            print(f"[!] Error binding to {host}:{port}: {e}")

            if retry_count < max_retries:
                wait_time = retry_count * 5  # Exponential backoff
                print(f"[!] Retrying in {wait_time} seconds... ({retry_count}/{max_retries})")
                time.sleep(wait_time)

                # If the port is in use, try a different port
                if e.errno == 10048:  # Address already in use
                    port += 1
                    print(f"[!] Port in use, trying port {port}")
            else:
                print(f"[!] Failed to bind after {max_retries} attempts, exiting")
                return

    if not server:
        print("[!] Failed to create server socket")
        return

    # Track active client threads
    active_threads = []

    # Main server loop
    while True:
        try:
            # Clean up completed threads
            active_threads = [t for t in active_threads if t.is_alive()]

            # Accept new connection
            conn, addr = server.accept()
            print(f"[+] New connection from {addr}")

            # Handle each client in a separate thread
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

            # Add to active threads list
            active_threads.append(client_thread)

            # Log active connections
            print(f"[+] Active connections: {len(active_threads)}")

        except socket.timeout:
            # This is normal, just continue
            continue
        except KeyboardInterrupt:
            print("[!] Server shutdown requested")
            break
        except Exception as e:
            print(f"[!] Error accepting connection: {e}")
            # Brief pause to avoid CPU spinning on repeated errors
            time.sleep(2)

    # Cleanup on exit
    try:
        server.close()
        print("[+] Server socket closed")
    except:
        pass

if __name__ == "__main__":
    # Start the socket server in a separate thread
    socket_thread = threading.Thread(target=start_server)
    socket_thread.daemon = True
    socket_thread.start()

    # Start the HTTP server in the main thread
    from proto.agent.http_handler import start_http_server
    start_http_server()
