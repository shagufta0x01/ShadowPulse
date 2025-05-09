import os
import pefile
import ctypes
from ctypes import wintypes
import html
import json

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
        self.process_handle = self.kernel32.OpenProcess(0x0410, False, self.pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if not self.process_handle:
            raise PermissionError(f"Could not open process {self.pid}: {ctypes.get_last_error()}")

        try:
            h_module_array = (wintypes.HMODULE * 1024)()
            cb_needed = wintypes.DWORD()

            if not self.psapi.EnumProcessModulesEx(self.process_handle, h_module_array, ctypes.sizeof(h_module_array),
                                              ctypes.byref(cb_needed), 0x03):  # LIST_MODULES_ALL
                raise OSError(f"Failed to enumerate modules: {ctypes.get_last_error()}")

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
        dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
        aslr_enabled = dll_char & 0x0040
        safeseh_enabled = dll_char & 0x0400
        dep_enabled = dll_char & 0x0100
        rebase_enabled = dll_char & 0x0020

        memory_protected = "Yes" if aslr_enabled and dep_enabled and safeseh_enabled else "No"

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
        for module in self.modules:
            module_path = module["path"]
            module_name = module["name"]
            base_address = module["base_address"]

            # Classify user-based DLLs vs system DLLs
            if "System32" in module_path or "Windows" in module_path:
                category = "System DLL"
            else:
                category = "User DLL"

            # Analyze the module
            if os.path.isfile(module_path):
                analysis = self.analyze_module(module_path, module_name, base_address)

                # Append the analysis results
                if category == "User DLL":
                    self.user_dll_analysis.append(analysis)
                else:
                    self.system_dll_analysis.append(analysis)

    def generate_html_report(self):
        """Generate an HTML report of the memory protection analysis."""
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
                        <h6 class="m-0 font-weight-bold">User DLLs</h6>
                    </div>
                    <div class="card-body p-0">
        """

        if self.user_dll_analysis:
            html_output += """
                        <div class="table-responsive">
                            <table class="table table-striped table-dark mb-0">
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
                                        <td><span class="badge bg-{'success text-dark' if analysis['ASLR'] == 'Enabled' else 'danger'}">{analysis["ASLR"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['DEP'] == 'Enabled' else 'danger'}">{analysis["DEP"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['SafeSEH'] == 'Enabled' else 'danger'}">{analysis["SafeSEH"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['Rebase'] == 'Enabled' else 'danger'}">{analysis["Rebase"]}</span></td>
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
                        <h6 class="m-0 font-weight-bold">System DLLs</h6>
                    </div>
                    <div class="card-body p-0">
        """

        if self.system_dll_analysis:
            html_output += """
                        <div class="table-responsive">
                            <table class="table table-striped table-dark mb-0">
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
                                        <td><span class="badge bg-{'success text-dark' if analysis['ASLR'] == 'Enabled' else 'danger'}">{analysis["ASLR"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['DEP'] == 'Enabled' else 'danger'}">{analysis["DEP"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['SafeSEH'] == 'Enabled' else 'danger'}">{analysis["SafeSEH"]}</span></td>
                                        <td><span class="badge bg-{'success text-dark' if analysis['Rebase'] == 'Enabled' else 'danger'}">{analysis["Rebase"]}</span></td>
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
