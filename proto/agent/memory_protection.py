import os
import pefile
import ctypes
from ctypes import wintypes
import html
import json
import sys

# Windows API structures and functions for retrieving loaded module information
class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


class MemoryProtectionCheck:
    """Class for analyzing memory protection features of a process."""

    def __init__(self, pid):
        self.pid = pid
        self.process_handle = None
        self.modules = []
        self.user_dll_analysis = []
        self.system_dll_analysis = []
        self.error = None

    def analyze(self):
        """Analyze the process and return the results."""
        try:
            # Load required Windows API functions
            self.psapi = ctypes.WinDLL('psapi')
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            # Define function prototypes
            self.psapi.EnumProcessModulesEx.restype = wintypes.BOOL
            self.psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]

            self.psapi.GetModuleInformation.restype = wintypes.BOOL
            self.psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]

            self.psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                                     ctypes.c_wchar_p, wintypes.DWORD]

            self.psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                                       ctypes.c_wchar_p, wintypes.DWORD]

            # Get loaded modules
            self.modules = self.get_loaded_modules()

            # Analyze modules
            self.analyze_loaded_modules()

            # Return results
            return {
                'user_dlls': self.user_dll_analysis,
                'system_dlls': self.system_dll_analysis,
                'error': self.error
            }
        except Exception as e:
            self.error = str(e)
            return {
                'user_dlls': [],
                'system_dlls': [],
                'error': self.error
            }
        finally:
            if self.process_handle:
                self.kernel32.CloseHandle(self.process_handle)

    def get_loaded_modules(self):
        """Retrieve all loaded modules for a process using the Windows API."""
        modules = []

        # Use the same access rights as the standalone script
        # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 0x0410
        self.process_handle = self.kernel32.OpenProcess(0x0410, False, self.pid)

        if not self.process_handle:
            error = ctypes.get_last_error()
            print(f"[-] Failed to open process {self.pid}: Error {error}")

            # Try with more limited access rights
            print(f"[*] Trying with more limited access rights...")
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            PROCESS_VM_READ = 0x0010
            self.process_handle = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, self.pid)

            if not self.process_handle:
                error = ctypes.get_last_error()
                print(f"[-] Failed to open process {self.pid} with limited rights: Error {error}")
                raise PermissionError(f"Could not open process {self.pid}: Error {error}")

        print(f"[+] Successfully opened process {self.pid}")

        try:
            h_module_array = (wintypes.HMODULE * 1024)()
            cb_needed = wintypes.DWORD()

            # Use LIST_MODULES_ALL (0x03) as in the standalone script
            if not self.psapi.EnumProcessModulesEx(self.process_handle, h_module_array, ctypes.sizeof(h_module_array),
                                          ctypes.byref(cb_needed), 0x03):  # LIST_MODULES_ALL
                error = ctypes.get_last_error()
                print(f"[-] Failed to enumerate modules: Error {error}")

                # Try with different list types if the first attempt fails
                module_list_types = [0x00, 0x01, 0x02]  # DEFAULT, 32BIT, 64BIT
                success = False

                for list_type in module_list_types:
                    if self.psapi.EnumProcessModulesEx(self.process_handle, h_module_array, ctypes.sizeof(h_module_array),
                                                  ctypes.byref(cb_needed), list_type):
                        print(f"[+] Successfully enumerated modules with list type: 0x{list_type:X}")
                        success = True
                        break
                    error = ctypes.get_last_error()
                    print(f"[-] Failed to enumerate modules with list type 0x{list_type:X}: Error {error}")

                if not success:
                    raise OSError(f"Failed to enumerate modules: Error {ctypes.get_last_error()}")
            else:
                print(f"[+] Successfully enumerated modules")

            module_count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)

            for i in range(module_count):
                h_module = h_module_array[i]

                # Get module base name
                module_name = ctypes.create_unicode_buffer(260)
                self.psapi.GetModuleBaseNameW(self.process_handle, h_module, module_name, ctypes.sizeof(module_name))

                # Get module file path
                module_path = ctypes.create_unicode_buffer(260)
                self.psapi.GetModuleFileNameExW(self.process_handle, h_module, module_path, ctypes.sizeof(module_path))

                # Get module information (base address)
                mod_info = MODULEINFO()
                if self.psapi.GetModuleInformation(self.process_handle, h_module, ctypes.byref(mod_info), ctypes.sizeof(mod_info)):
                    modules.append({
                        "name": module_name.value,
                        "path": module_path.value,
                        "base_address": hex(mod_info.lpBaseOfDll)
                    })

        except Exception as e:
            self.error = str(e)

        return modules

    def analyze_module(self, file, module_name, base_address):
        """Analyze a module for memory protection features."""
        try:
            pe = pefile.PE(file)
        except pefile.PEFormatError:
            return {
                "Module": module_name,
                "Base Address": base_address,
                "ASLR": "N/A",
                "DEP": "N/A",
                "SafeSEH": "N/A",
                "Rebase": "N/A",
                "Memory Protected": "N/A"
            }
        except Exception as e:
            return {
                "Module": module_name,
                "Base Address": base_address,
                "ASLR": f"Error: {e}",
                "DEP": "N/A",
                "SafeSEH": "N/A",
                "Rebase": "N/A",
                "Memory Protected": "Unknown"
            }

        # Extract DllCharacteristics and flags
        try:
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            aslr_enabled = bool(dll_char & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            safeseh_enabled = bool(dll_char & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
            dep_enabled = bool(dll_char & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            rebase_enabled = bool(dll_char & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA

            memory_protected = "Yes" if aslr_enabled and dep_enabled and safeseh_enabled else "No"
        except Exception as e:
            print(f"[!] Error extracting DLL characteristics for {module_name}: {str(e)}")
            return {
                "Module": module_name,
                "Base Address": base_address,
                "ASLR": "Error",
                "DEP": "Error",
                "SafeSEH": "Error",
                "Rebase": "Error",
                "Memory Protected": "Unknown"
            }

        return {
            "Module": module_name,
            "Base Address": base_address,
            "ASLR": "Enabled" if aslr_enabled else "Disabled",
            "DEP": "Enabled" if dep_enabled else "Disabled",
            "SafeSEH": "Enabled" if safeseh_enabled else "Disabled",
            "Rebase": "Enabled" if rebase_enabled else "Disabled",
            "Memory Protected": memory_protected
        }

    def analyze_loaded_modules(self):
        """Analyze all loaded modules for memory protection features."""
        total_modules = len(self.modules)
        print(f"[+] Analyzing {total_modules} loaded modules for process {self.pid}")

        if total_modules == 0:
            print(f"[!] No modules found for process {self.pid}. This may be due to insufficient permissions.")
            self.error = f"No modules found for process {self.pid}. This may be due to insufficient permissions or the process has terminated."
            return

        analyzed_modules = 0
        access_errors = 0

        # Process modules in batches to avoid overwhelming the system
        batch_size = 10
        for i, module in enumerate(self.modules):
            # Print progress every batch_size modules
            if i % batch_size == 0 or i == 0 or i == total_modules - 1:
                progress_percent = int((i / total_modules) * 100)
                print(f"[+] Analyzing module {i+1}/{total_modules} ({progress_percent}% complete)")

            module_path = module["path"]
            module_name = module["name"]
            base_address = module["base_address"]

            # Classify user-based DLLs vs system DLLs
            if "System32" in module_path or "Windows" in module_path:
                category = "System DLL"
            else:
                category = "User DLL"

            # Analyze the module
            try:
                if os.path.isfile(module_path):
                    analysis = self.analyze_module(module_path, module_name, base_address)
                    analyzed_modules += 1

                    # Append the analysis results
                    if category == "User DLL":
                        self.user_dll_analysis.append(analysis)
                    else:
                        self.system_dll_analysis.append(analysis)
                else:
                    print(f"[!] Module file not found: {module_path}")
                    access_errors += 1
            except PermissionError as pe:
                print(f"[!] Permission error analyzing module {module_name}: {str(pe)}")
                access_errors += 1
            except Exception as e:
                print(f"[!] Error analyzing module {module_name}: {str(e)}")
                access_errors += 1

        print(f"[+] Module analysis complete: {len(self.user_dll_analysis)} user DLLs, {len(self.system_dll_analysis)} system DLLs")

        if analyzed_modules == 0 and access_errors > 0:
            self.error = f"Could not analyze any modules due to permission issues. Try running with elevated privileges."
            print(f"[!] {self.error}")

    def generate_html_report(self):
        """Generate an HTML report of the memory protection analysis."""
        # Check if there was an error during analysis
        if self.error:
            html_output = f"""
            <div class="alert alert-danger mb-4">
                <h5><i class="fas fa-exclamation-triangle mr-2"></i>Error During Analysis</h5>
                <p>{html.escape(self.error)}</p>
                <hr>
                <p class="mb-0">
                    <strong>Possible solutions:</strong>
                    <ul>
                        <li>Run the application with administrator privileges</li>
                        <li>Try analyzing a different process</li>
                        <li>Ensure the process is still running</li>
                        <li>Check if any security software is blocking access</li>
                    </ul>
                </p>
            </div>

            <div class="mb-4">
                <h5>Memory Protection Summary for PID: {self.pid}</h5>
                <div class="progress mb-2">
                    <div class="progress-bar bg-danger" role="progressbar" style="width: 0%"
                         aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                </div>
                <p class="text-muted">Overall memory protection score: 0% (Poor)</p>
            </div>
            """
            return html_output

        # Calculate protection score
        total_modules = len(self.user_dll_analysis) + len(self.system_dll_analysis)
        if total_modules == 0:
            protection_score = 0
        else:
            protected_modules = 0
            for analysis in self.user_dll_analysis + self.system_dll_analysis:
                if analysis["Memory Protected"] == "Yes":
                    protected_modules += 1
            protection_score = int((protected_modules / total_modules) * 100)

        # Determine score color and text
        if protection_score >= 80:
            score_color = "success"
            score_text = "Good"
        elif protection_score >= 60:
            score_color = "warning"
            score_text = "Fair"
        else:
            score_color = "danger"
            score_text = "Poor"

        # Generate HTML
        html_output = f"""
        <div class="mb-4">
            <h5>Memory Protection Summary for PID: {self.pid}</h5>
            <div class="progress mb-2">
                <div class="progress-bar bg-{score_color}" role="progressbar" style="width: {protection_score}%"
                     aria-valuenow="{protection_score}" aria-valuemin="0" aria-valuemax="100">{protection_score}%</div>
            </div>
            <p class="text-muted">Overall memory protection score: {protection_score}% ({score_text})</p>
        </div>
        """

        # Add user DLLs section
        html_output += """
        <div class="row">
            <div class="col-md-12 mb-4">
                <div class="card">
                    <div class="card-header py-3">
                        <h6 class="m-0 font-weight-bold text-primary">User DLLs</h6>
                    </div>
                    <div class="card-body p-0">
        """

        if self.user_dll_analysis:
            html_output += """
                        <div class="table-responsive">
                            <table class="table table-striped mb-0">
                                <thead>
                                    <tr>
                                        <th>Module</th>
                                        <th>Base Address</th>
                                        <th>ASLR</th>
                                        <th>DEP</th>
                                        <th>SafeSEH</th>
                                        <th>Rebase</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            for analysis in self.user_dll_analysis:
                html_output += f"""
                                    <tr>
                                        <td>{html.escape(analysis["Module"])}</td>
                                        <td>{html.escape(analysis["Base Address"])}</td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['ASLR'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["ASLR"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['DEP'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["DEP"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['SafeSEH'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["SafeSEH"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['Rebase'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["Rebase"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                """

            html_output += """
                                </tbody>
                            </table>
                        </div>
            """
        else:
            html_output += """
                        <div class="alert alert-info m-3">
                            <i class="fas fa-info-circle mr-2"></i>
                            No user DLLs found or insufficient permissions to access them.
                        </div>
            """

        html_output += """
                    </div>
                </div>
            </div>
        </div>
        """

        # Add system DLLs section
        html_output += """
        <div class="row">
            <div class="col-md-12 mb-4">
                <div class="card">
                    <div class="card-header py-3">
                        <h6 class="m-0 font-weight-bold text-primary">System DLLs</h6>
                    </div>
                    <div class="card-body p-0">
        """

        if self.system_dll_analysis:
            html_output += """
                        <div class="table-responsive">
                            <table class="table table-striped mb-0">
                                <thead>
                                    <tr>
                                        <th>Module</th>
                                        <th>Base Address</th>
                                        <th>ASLR</th>
                                        <th>DEP</th>
                                        <th>SafeSEH</th>
                                        <th>Rebase</th>
                                    </tr>
                                </thead>
                                <tbody>
            """

            for analysis in self.system_dll_analysis:
                html_output += f"""
                                    <tr>
                                        <td>{html.escape(analysis["Module"])}</td>
                                        <td>{html.escape(analysis["Base Address"])}</td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['ASLR'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["ASLR"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['DEP'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["DEP"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['SafeSEH'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["SafeSEH"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                <tr>
                                                    <td style="background-color: {'#28a745' if analysis['Rebase'] == 'Enabled' else '#dc3545'}; color: #000000 !important; font-weight: bold; text-align: center; padding: 5px;">
                                                        <span style="color: #000000 !important;">{analysis["Rebase"]}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                """

            html_output += """
                                </tbody>
                            </table>
                        </div>
            """
        else:
            html_output += """
                        <div class="alert alert-info m-3">
                            <i class="fas fa-info-circle mr-2"></i>
                            No system DLLs found or insufficient permissions to access them.
                        </div>
            """

        html_output += """
                    </div>
                </div>
            </div>
        </div>
        """

        # Add recommendations
        html_output += """
        <div class="alert alert-info">
            <h6 class="font-weight-bold">Recommendations:</h6>
            <ul class="mb-0">
                <li>Enable ASLR for all modules to improve security</li>
                <li>Ensure DEP is enabled for all modules</li>
                <li>Consider updating modules with missing SafeSEH protection</li>
                <li>For critical applications, ensure all memory protection features are enabled</li>
            </ul>
        </div>
        """

        return html_output

    def print_table(self):
        """Print a colored table of the memory protection analysis to the terminal."""
        # ANSI color codes
        GREEN = "\033[92m"  # Green for Enabled
        RED = "\033[91m"    # Red for Disabled
        YELLOW = "\033[93m" # Yellow for headers
        CYAN = "\033[96m"   # Cyan for module names
        RESET = "\033[0m"   # Reset to default color

        # Check if there was an error during analysis
        if self.error:
            print(f"{RED}Error During Analysis: {self.error}{RESET}")
            print(f"{YELLOW}Possible solutions:{RESET}")
            print("- Run the application with administrator privileges")
            print("- Try analyzing a different process")
            print("- Ensure the process is still running")
            print("- Check if any security software is blocking access")
            return

        # Calculate protection score
        total_modules = len(self.user_dll_analysis) + len(self.system_dll_analysis)
        if total_modules == 0:
            protection_score = 0
        else:
            protected_modules = 0
            for analysis in self.user_dll_analysis + self.system_dll_analysis:
                if analysis["Memory Protected"] == "Yes":
                    protected_modules += 1
            protection_score = int((protected_modules / total_modules) * 100)

        # Print summary
        print(f"{YELLOW}Memory Protection Summary for PID: {self.pid}{RESET}")
        print(f"Overall memory protection score: {protection_score}%")
        print()

        # Print User DLLs
        print(f"{YELLOW}User DLLs{RESET}")
        if self.user_dll_analysis:
            # Print header
            print(f"{YELLOW}{'Module':<30} {'Base Address':<18} {'ASLR':<10} {'DEP':<10} {'SafeSEH':<10} {'Rebase':<10}{RESET}")
            print("-" * 90)

            # Print each module
            for analysis in self.user_dll_analysis:
                module = analysis["Module"]
                base_addr = analysis["Base Address"]
                aslr = f"{GREEN if analysis['ASLR'] == 'Enabled' else RED}{analysis['ASLR']}{RESET}"
                dep = f"{GREEN if analysis['DEP'] == 'Enabled' else RED}{analysis['DEP']}{RESET}"
                safeseh = f"{GREEN if analysis['SafeSEH'] == 'Enabled' else RED}{analysis['SafeSEH']}{RESET}"
                rebase = f"{GREEN if analysis['Rebase'] == 'Enabled' else RED}{analysis['Rebase']}{RESET}"

                print(f"{CYAN}{module:<30}{RESET} {base_addr:<18} {aslr:<25} {dep:<25} {safeseh:<25} {rebase:<25}")
        else:
            print("No user DLLs found or insufficient permissions to access them.")

        print()

        # Print System DLLs
        print(f"{YELLOW}System DLLs{RESET}")
        if self.system_dll_analysis:
            # Print header
            print(f"{YELLOW}{'Module':<30} {'Base Address':<18} {'ASLR':<10} {'DEP':<10} {'SafeSEH':<10} {'Rebase':<10}{RESET}")
            print("-" * 90)

            # Print each module
            for analysis in self.system_dll_analysis:
                module = analysis["Module"]
                base_addr = analysis["Base Address"]
                aslr = f"{GREEN if analysis['ASLR'] == 'Enabled' else RED}{analysis['ASLR']}{RESET}"
                dep = f"{GREEN if analysis['DEP'] == 'Enabled' else RED}{analysis['DEP']}{RESET}"
                safeseh = f"{GREEN if analysis['SafeSEH'] == 'Enabled' else RED}{analysis['SafeSEH']}{RESET}"
                rebase = f"{GREEN if analysis['Rebase'] == 'Enabled' else RED}{analysis['Rebase']}{RESET}"

                print(f"{CYAN}{module:<30}{RESET} {base_addr:<18} {aslr:<25} {dep:<25} {safeseh:<25} {rebase:<25}")
        else:
            print("No system DLLs found or insufficient permissions to access them.")

        print()

        # Print recommendations
        print(f"{YELLOW}Recommendations:{RESET}")
        print("- Enable ASLR for all modules to improve security")
        print("- Ensure DEP is enabled for all modules")
        print("- Consider updating modules with missing SafeSEH protection")
        print("- For critical applications, ensure all memory protection features are enabled")