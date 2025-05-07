import os
import socket
import threading
import time
import mimetypes
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from proto.agent.handlers import command_dispatcher
from proto.pro.protocol import *

# Initialize mimetypes
mimetypes.init()

# Define the base directory for static files
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# Ensure the static directory exists
os.makedirs(os.path.join(STATIC_DIR, 'js'), exist_ok=True)

class AgentHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the agent."""
    
    def log_message(self, format, *args):
        """Override to customize logging."""
        print(f"[HTTP] {self.address_string()} - {format % args}")
    
    def send_response_with_headers(self, code, content_type, content_length=None):
        """Send response with common headers."""
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        if content_length is not None:
            self.send_header('Content-Length', str(content_length))
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
    
    def serve_static_file(self, file_path):
        """Serve a static file."""
        try:
            # Normalize the path to prevent directory traversal attacks
            normalized_path = os.path.normpath(file_path)
            if normalized_path.startswith('..'):
                self.send_error(403, "Forbidden")
                return
            
            # Construct the full path
            full_path = os.path.join(STATIC_DIR, normalized_path)
            
            # Check if the file exists
            if not os.path.isfile(full_path):
                self.send_error(404, "File not found")
                return
            
            # Determine the content type
            content_type, _ = mimetypes.guess_type(full_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            # Get the file size
            file_size = os.path.getsize(full_path)
            
            # Send headers
            self.send_response_with_headers(200, content_type, file_size)
            
            # Send the file content
            with open(full_path, 'rb') as f:
                self.wfile.write(f.read())
                
            print(f"[HTTP] Served static file: {file_path}")
            
        except Exception as e:
            print(f"[HTTP] Error serving static file {file_path}: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_GET(self):
        """Handle GET requests."""
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query = urllib.parse.parse_qs(parsed_url.query)
            
            # Handle static file requests
            if path.startswith('/static/'):
                file_path = path[8:]  # Remove '/static/' prefix
                self.serve_static_file(file_path)
                return
            
            # Handle memory protection analysis
            if path == '/memory-protection':
                pid = query.get('pid', [''])[0]
                if not pid:
                    self.send_error(400, "Missing PID parameter")
                    return
                
                # Call the command dispatcher with the memory protection command
                response_data = command_dispatcher(CMD_ANALYZE_PROCESS_MEMORY, ip=pid)
                
                # Send the response
                self.send_response_with_headers(200, 'text/html; charset=utf-8')
                self.wfile.write(response_data)
                return
            
            # Handle other commands based on the path
            if path == '/os-info':
                response_data = command_dispatcher(CMD_OS_INFO)
                self.send_response_with_headers(200, 'text/html; charset=utf-8')
                self.wfile.write(response_data)
                return
            
            if path == '/network-info':
                response_data = command_dispatcher(CMD_NETWORK_INFO)
                self.send_response_with_headers(200, 'text/html; charset=utf-8')
                self.wfile.write(response_data)
                return
            
            if path == '/processes':
                response_data = command_dispatcher(CMD_GET_RUNNING_PROCESSES)
                self.send_response_with_headers(200, 'text/html; charset=utf-8')
                self.wfile.write(response_data)
                return
            
            # Default response for root path
            if path == '/' or path == '/index.html':
                # Simple HTML page with links to available commands
                html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Agent Web Interface</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
                    <script src="/static/js/data-persistence.js"></script>
                </head>
                <body>
                    <div class="container mt-4">
                        <h1>Agent Web Interface</h1>
                        <div class="list-group mt-4">
                            <a href="/os-info" class="list-group-item list-group-item-action">System Information</a>
                            <a href="/network-info" class="list-group-item list-group-item-action">Network Information</a>
                            <a href="/processes" class="list-group-item list-group-item-action">Running Processes</a>
                        </div>
                    </div>
                </body>
                </html>
                """
                self.send_response_with_headers(200, 'text/html; charset=utf-8', len(html))
                self.wfile.write(html.encode())
                return
            
            # If we get here, the path wasn't recognized
            self.send_error(404, "Not found")
            
        except Exception as e:
            print(f"[HTTP] Error handling GET request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests."""
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            
            # Read the request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            
            # Handle the request based on the path
            if path == '/command':
                # Parse the command from the request body
                params = urllib.parse.parse_qs(body)
                cmd = params.get('cmd', [''])[0]
                payload = params.get('payload', [''])[0]
                
                # Map the command string to a command code
                cmd_code = None
                for name, value in globals().items():
                    if name.startswith('CMD_') and name.lower() == f"cmd_{cmd.lower()}":
                        cmd_code = value
                        break
                
                if cmd_code is None:
                    self.send_error(400, f"Unknown command: {cmd}")
                    return
                
                # Call the command dispatcher
                response_data = command_dispatcher(cmd_code, ip=payload)
                
                # Send the response
                self.send_response_with_headers(200, 'text/html; charset=utf-8')
                self.wfile.write(response_data)
                return
            
            # If we get here, the path wasn't recognized
            self.send_error(404, "Not found")
            
        except Exception as e:
            print(f"[HTTP] Error handling POST request: {e}")
            self.send_error(500, f"Internal server error: {str(e)}")

def start_http_server(host="0.0.0.0", port=23033):
    """Start the HTTP server."""
    try:
        server = HTTPServer((host, port), AgentHTTPHandler)
        print(f"[HTTP] Server started on http://{host}:{port}")
        server.serve_forever()
    except Exception as e:
        print(f"[HTTP] Error starting HTTP server: {e}")

if __name__ == "__main__":
    start_http_server()
