"""
Build script for creating an executable of the agent listener.
This script uses PyInstaller to create a standalone executable.
"""

import os
import sys
import shutil
import subprocess
import platform

def check_requirements():
    """Check if required packages are installed."""
    try:
        import PyInstaller
        print("[+] PyInstaller is installed.")
    except ImportError:
        print("[!] PyInstaller is not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("[+] PyInstaller installed successfully.")
    
    # Check for other required packages
    required_packages = [
        "scapy",
        "mac_vendor_lookup",
        "wmi",
    ]
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"[+] {package} is installed.")
        except ImportError:
            print(f"[!] {package} is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"[+] {package} installed successfully.")

def build_executable():
    """Build the executable using PyInstaller."""
    print("[+] Starting build process...")
    
    # Create a temporary entry point script
    with open("agent_listener_entry.py", "w") as f:
        f.write("""
# Entry point for the agent listener executable
import sys
import os

# Add the current directory to the path so we can import the proto module
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import and run the agent listener
from proto.agent.agent_listener import start_server
from proto.agent.http_handler import start_http_server
import threading

if __name__ == "__main__":
    # Start the socket server in a separate thread
    socket_thread = threading.Thread(target=start_server)
    socket_thread.daemon = True
    socket_thread.start()
    
    # Start the HTTP server in the main thread
    start_http_server()
""")
    
    # Determine the icon file based on the platform
    icon_option = []
    if platform.system() == "Windows":
        # Create a simple icon file if it doesn't exist
        if not os.path.exists("agent_icon.ico"):
            try:
                # Try to use an existing icon if available
                if os.path.exists("docs/images/rex-logo.png"):
                    from PIL import Image
                    import io
                    img = Image.open("docs/images/rex-logo.png")
                    img.save("agent_icon.ico")
                    print("[+] Created icon file from rex-logo.png")
                    icon_option = ["--icon=agent_icon.ico"]
            except Exception as e:
                print(f"[!] Could not create icon: {e}")
                print("[!] Continuing without icon...")
    
    # Build the executable
    pyinstaller_command = [
        "pyinstaller",
        "--onefile",  # Create a single executable file
        "--name", "agent_listener",  # Name of the executable
        "--clean",  # Clean PyInstaller cache
        "--log-level", "INFO",  # Logging level
        "--hidden-import=scapy.layers.all",  # Include scapy layers
        "--hidden-import=mac_vendor_lookup",  # Include mac_vendor_lookup
        "--hidden-import=wmi",  # Include wmi
        "--add-data", "proto;proto",  # Include the proto directory
    ]
    
    # Add icon if available
    if icon_option:
        pyinstaller_command.extend(icon_option)
    
    # Add the entry point script
    pyinstaller_command.append("agent_listener_entry.py")
    
    # Run PyInstaller
    print(f"[+] Running PyInstaller with command: {' '.join(pyinstaller_command)}")
    subprocess.check_call(pyinstaller_command)
    
    # Clean up temporary files
    if os.path.exists("agent_listener_entry.py"):
        os.remove("agent_listener_entry.py")
    
    # Copy the executable to the current directory
    if platform.system() == "Windows":
        exe_path = os.path.join("dist", "agent_listener.exe")
        if os.path.exists(exe_path):
            shutil.copy(exe_path, ".")
            print(f"[+] Executable created: {os.path.abspath('agent_listener.exe')}")
    else:
        exe_path = os.path.join("dist", "agent_listener")
        if os.path.exists(exe_path):
            shutil.copy(exe_path, ".")
            print(f"[+] Executable created: {os.path.abspath('agent_listener')}")

def main():
    """Main function."""
    print("=" * 60)
    print("Agent Listener Executable Builder")
    print("=" * 60)
    
    # Check requirements
    check_requirements()
    
    # Build the executable
    build_executable()
    
    print("=" * 60)
    print("[+] Build process completed.")
    print("=" * 60)

if __name__ == "__main__":
    main()
