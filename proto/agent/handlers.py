from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import socket
import platform
import json
import os
import subprocess
import wmi
import html
from datetime import datetime
from pro.protocol import *

# Helper function to generate HTML-formatted output
def format_html_output(title, sections):
    """
    Generate HTML-formatted output for web display

    Args:
        title (str): The main title of the report
        sections (list): List of dictionaries with 'title' and 'content' keys

    Returns:
        str: HTML-formatted output
    """
    css = """
    <style>
        .report-container {
            font-family: 'Segoe UI', Arial, sans-serif;
            max-width: 100%;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .report-header {
            background-color: #0d6efd;
            color: white;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .report-title {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }
        .report-timestamp {
            font-size: 14px;
            opacity: 0.9;
        }
        .report-section {
            background-color: white;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section-header {
            background-color: #e9ecef;
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
            font-weight: 600;
            font-size: 18px;
            color: #212529;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-status {
            font-size: 14px;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .status-success {
            background-color: #d1e7dd;
            color: #0f5132;
        }
        .status-error {
            background-color: #f8d7da;
            color: #842029;
        }
        .section-content {
            padding: 15px;
            overflow-x: auto;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        .data-table th, .data-table td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        .data-table th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .data-table tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        .data-table tr:hover {
            background-color: #e9ecef;
        }
        .error-message {
            color: #842029;
            background-color: #f8d7da;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .summary-section {
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
        }
        .summary-title {
            font-weight: 600;
            margin-bottom: 10px;
        }
        .summary-stats {
            display: flex;
            gap: 20px;
        }
        .stat-item {
            background-color: white;
            padding: 10px 15px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .stat-label {
            font-size: 14px;
            color: #6c757d;
        }
        .stat-value {
            font-size: 20px;
            font-weight: 600;
            margin-top: 5px;
        }
        .success-value {
            color: #198754;
        }
        .error-value {
            color: #dc3545;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 14px;
        }
        .key-value-table {
            width: 100%;
            border-collapse: collapse;
        }
        .key-value-table td {
            padding: 8px 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .key-value-table td:first-child {
            font-weight: 600;
            width: 30%;
        }
        .category-header {
            margin: 25px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #0d6efd;
        }
        .category-header h2 {
            font-size: 22px;
            color: #0d6efd;
            margin: 0;
            font-weight: 600;
        }
    </style>
    """

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Start building HTML
    html_output = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{html.escape(title)}</title>
        {css}
    </head>
    <body>
        <div class="report-container">
            <div class="report-header">
                <h1 class="report-title">{html.escape(title)}</h1>
                <div class="report-timestamp">Generated: {timestamp}</div>
            </div>
    """

    # Group sections by category
    categorized_sections = {}
    for section in sections:
        if section.get('summary'):
            continue  # Skip summary section

        section_title = section.get('title', 'Untitled Section')
        section_content = section.get('content', '')
        section_status = section.get('status', 'success')
        section_category = section.get('category', 'General')

        if section_category not in categorized_sections:
            categorized_sections[section_category] = []

        categorized_sections[section_category].append({
            'title': section_title,
            'content': section_content,
            'status': section_status
        })

    # Add categories and their sections
    for category, category_sections in categorized_sections.items():
        # Add category header
        html_output += f"""
            <div class="category-header">
                <h2>{html.escape(category)}</h2>
            </div>
        """

        # Add sections in this category
        for section in category_sections:
            section_title = section.get('title', 'Untitled Section')
            section_content = section.get('content', '')
            section_status = section.get('status', 'success')

            status_class = 'status-success' if section_status == 'success' else 'status-error'
            status_text = 'Success' if section_status == 'success' else 'Error'

            html_output += f"""
                <div class="report-section">
                    <div class="section-header">
                        <span>{html.escape(section_title)}</span>
                        <span class="section-status {status_class}">{status_text}</span>
                    </div>
                    <div class="section-content">
                        {section_content}
                    </div>
                </div>
            """

    # Add summary if provided
    if any(section.get('summary') for section in sections):
        summary_section = next((s for s in sections if s.get('summary')), {})
        success_count = summary_section.get('success_count', 0)
        failure_count = summary_section.get('failure_count', 0)

        html_output += f"""
            <div class="summary-section">
                <div class="summary-title">Report Summary</div>
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="stat-label">Successful Sections</div>
                        <div class="stat-value success-value">{success_count}</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Failed Sections</div>
                        <div class="stat-value error-value">{failure_count}</div>
                    </div>
                </div>
            </div>
        """

    # Close HTML
    html_output += """
        </div>
    </body>
    </html>
    """

    return html_output

# Helper functions for formatting data as HTML
def text_to_html_table(text):
    """Convert plain text with key-value pairs to HTML table"""
    if not text:
        return "<p>No data available</p>"

    # If it's already HTML content, return it as is
    if text.strip().startswith('<') and ('<table' in text or '<div' in text):
        return text

    lines = text.strip().split('\n')

    # Check if this is a key-value format (contains colons)
    if any(':' in line for line in lines if line and not line.startswith('-')):
        html_table = '<div class="table-responsive"><table class="key-value-table" style="width:100%">'

        for line in lines:
            line = line.strip()
            if not line or line.startswith('-'):
                continue

            if ':' in line:
                key, value = line.split(':', 1)
                html_table += f'<tr><td style="width:30%; font-weight:bold;">{html.escape(key.strip())}</td><td style="word-break:break-word;">{html.escape(value.strip())}</td></tr>'
            else:
                html_table += f'<tr><td colspan="2">{html.escape(line)}</td></tr>'

        html_table += '</table></div>'
        return html_table

    # If it's not key-value, just wrap in pre tags
    return f'<pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(text)}</pre>'

def format_system_info(info_text):
    """Format system information as HTML"""
    if not info_text:
        return "<p>No system information available</p>"

    # If it's already HTML content, return it as is
    if info_text.strip().startswith('<') and ('<table' in info_text or '<div' in info_text):
        return info_text

    # Parse the text to extract system info
    lines = info_text.strip().split('\n')
    html_output = '<div class="table-responsive"><table class="key-value-table" style="width:100%">'

    for line in lines:
        line = line.strip()
        if not line or line.startswith('-') or line.startswith('=') or ':' not in line:
            continue

        key, value = line.split(':', 1)
        html_output += f'<tr><td style="width:30%; font-weight:bold;">{html.escape(key.strip())}</td><td style="word-break:break-word;">{html.escape(value.strip())}</td></tr>'

    html_output += '</table></div>'
    return html_output

def format_error_message(error_text):
    """Format error message as HTML"""
    # If it's already HTML content, return it as is
    if error_text.strip().startswith('<') and ('<div' in error_text):
        return error_text

    return f'<div class="error-message alert alert-danger">{html.escape(error_text)}</div>'

c = wmi.WMI()

def run_powershell_command(command, timeout=30):
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Command timed out after {} seconds".format(timeout)
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {str(e)}"

class OsInfo:
    def format_output(self, title, data, headers=None, is_table=True):
        """
        Format output in both text and HTML formats

        Args:
            title (str): The title of the output
            data (list): List of dictionaries or list of lists with the data
            headers (list, optional): List of column headers. Required for list of lists data.
            is_table (bool): Whether to format as a table or key-value pairs

        Returns:
            dict: Dictionary with 'text' and 'html' keys
        """
        # Create text output
        text_output = f"{title}:\n"
        text_output += "-" * 70 + "\n"

        # Create HTML output
        if is_table:
            # For table format
            html_output = f'<div class="table-responsive"><table class="table table-striped table-hover" style="width:100%">'

            # Add headers
            html_output += '<thead class="table-dark"><tr>'

            if isinstance(data[0], dict):
                # Extract headers from dictionary keys if not provided
                if not headers:
                    headers = list(data[0].keys())

                # Add headers to HTML
                for header in headers:
                    html_output += f'<th>{html.escape(str(header))}</th>'
                html_output += '</tr></thead><tbody>'

                # Add header row to text output
                header_row = ""
                for header in headers:
                    header_row += f"{str(header):<20} "
                text_output += header_row + "\n"
                text_output += "-" * 70 + "\n"

                # Add data rows
                for row in data:
                    # HTML row
                    html_output += '<tr>'
                    for header in headers:
                        value = row.get(header, "")
                        html_output += f'<td style="word-break:break-word;">{html.escape(str(value))}</td>'
                    html_output += '</tr>'

                    # Text row
                    text_row = ""
                    for header in headers:
                        value = row.get(header, "")
                        text_row += f"{str(value):<20} "
                    text_output += text_row + "\n"
            else:
                # For list of lists format
                if not headers:
                    raise ValueError("Headers are required for list of lists data")

                # Add headers to HTML
                for header in headers:
                    html_output += f'<th>{html.escape(str(header))}</th>'
                html_output += '</tr></thead><tbody>'

                # Add header row to text output
                header_row = ""
                for header in headers:
                    col_width = 20
                    header_row += f"{str(header):<{col_width}} "
                text_output += header_row + "\n"
                text_output += "-" * 70 + "\n"

                # Add data rows
                for row in data:
                    # HTML row
                    html_output += '<tr>'
                    for value in row:
                        html_output += f'<td style="word-break:break-word;">{html.escape(str(value))}</td>'
                    html_output += '</tr>'

                    # Text row
                    text_row = ""
                    for value in row:
                        col_width = 20
                        text_row += f"{str(value):<{col_width}} "
                    text_output += text_row + "\n"

            html_output += '</tbody></table></div>'
        else:
            # For key-value format
            html_output = '<div class="table-responsive"><table class="key-value-table" style="width:100%">'

            for item in data:
                if isinstance(item, dict) and 'key' in item and 'value' in item:
                    # HTML row with word-wrap for value column
                    html_output += f'<tr><td style="width:30%; font-weight:bold;">{html.escape(str(item["key"]))}</td><td style="word-break:break-word;">{html.escape(str(item["value"]))}</td></tr>'

                    # Text row
                    text_output += f"{str(item['key']):<30} {str(item['value'])}\n"
                elif isinstance(item, tuple) and len(item) == 2:
                    # HTML row with word-wrap for value column
                    html_output += f'<tr><td style="width:30%; font-weight:bold;">{html.escape(str(item[0]))}</td><td style="word-break:break-word;">{html.escape(str(item[1]))}</td></tr>'

                    # Text row
                    text_output += f"{str(item[0]):<30} {str(item[1])}\n"

            html_output += '</table></div>'

        return {
            'text': text_output,
            'html': html_output
        }

    def handle_basic_info(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get basic system information
            $systemInfo = @{
                "System Overview" = @()
                "CPU Information" = @()
                "Memory Status" = @()
                "Disk Information" = @()
            }

            # System overview
            $systemInfo["System Overview"] += @{
                "Name" = "OS Name"
                "Value" = [System.Environment]::OSVersion.VersionString
            }
            $systemInfo["System Overview"] += @{
                "Name" = "Computer Name"
                "Value" = [System.Environment]::MachineName
            }
            $systemInfo["System Overview"] += @{
                "Name" = "User Name"
                "Value" = [System.Environment]::UserName
            }
            $systemInfo["System Overview"] += @{
                "Name" = "Domain Name"
                "Value" = [System.Environment]::UserDomainName
            }
            $systemInfo["System Overview"] += @{
                "Name" = "System Directory"
                "Value" = [System.Environment]::SystemDirectory
            }
            $systemInfo["System Overview"] += @{
                "Name" = ".NET Version"
                "Value" = [System.Environment]::Version.ToString()
            }
            $systemInfo["System Overview"] += @{
                "Name" = "64-bit OS"
                "Value" = [System.Environment]::Is64BitOperatingSystem
            }
            $systemInfo["System Overview"] += @{
                "Name" = "64-bit Process"
                "Value" = [System.Environment]::Is64BitProcess
            }
            # Get system uptime (compatible with older PowerShell versions)
            try {
                # Try using Get-Uptime (PowerShell 5.1+)
                $uptime = (Get-Uptime).ToString()
            } catch {
                # Fallback for older PowerShell versions
                $os = Get-WmiObject -Class Win32_OperatingSystem
                $lastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                $uptime = (Get-Date) - $lastBoot
                $uptime = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
            }

            $systemInfo["System Overview"] += @{
                "Name" = "System Uptime"
                "Value" = $uptime
            }

            # CPU information
            try {
                $processor = Get-WmiObject -Class Win32_Processor
                $systemInfo["CPU Information"] += @{
                    "Name" = "Processor Name"
                    "Value" = $processor.Name
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Manufacturer"
                    "Value" = $processor.Manufacturer
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Description"
                    "Value" = $processor.Description
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Number of Cores"
                    "Value" = $processor.NumberOfCores
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Number of Logical Processors"
                    "Value" = $processor.NumberOfLogicalProcessors
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Current Clock Speed"
                    "Value" = "$($processor.CurrentClockSpeed) MHz"
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "Max Clock Speed"
                    "Value" = "$($processor.MaxClockSpeed) MHz"
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "L2 Cache Size"
                    "Value" = "$($processor.L2CacheSize) KB"
                }
                $systemInfo["CPU Information"] += @{
                    "Name" = "L3 Cache Size"
                    "Value" = "$($processor.L3CacheSize) KB"
                }
            } catch {
                $systemInfo["CPU Information"] += @{
                    "Name" = "Error"
                    "Value" = "Could not retrieve CPU information: $($_.Exception.Message)"
                }
            }

            # Memory status
            try {
                $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem

                $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
                $freeMemoryGB = [math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
                $usedMemoryGB = [math]::Round($totalMemoryGB - $freeMemoryGB, 2)
                $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1)

                $systemInfo["Memory Status"] += @{
                    "Name" = "Total Physical Memory"
                    "Value" = "$totalMemoryGB GB"
                }
                $systemInfo["Memory Status"] += @{
                    "Name" = "Free Physical Memory"
                    "Value" = "$freeMemoryGB GB"
                }
                $systemInfo["Memory Status"] += @{
                    "Name" = "Used Physical Memory"
                    "Value" = "$usedMemoryGB GB ($memoryUsagePercent%)"
                }

                $totalVirtualMemoryGB = [math]::Round($operatingSystem.TotalVirtualMemorySize / 1MB, 2)
                $freeVirtualMemoryGB = [math]::Round($operatingSystem.FreeVirtualMemory / 1MB, 2)
                $usedVirtualMemoryGB = [math]::Round($totalVirtualMemoryGB - $freeVirtualMemoryGB, 2)
                $virtualMemoryUsagePercent = [math]::Round(($usedVirtualMemoryGB / $totalVirtualMemoryGB) * 100, 1)

                $systemInfo["Memory Status"] += @{
                    "Name" = "Total Virtual Memory"
                    "Value" = "$totalVirtualMemoryGB GB"
                }
                $systemInfo["Memory Status"] += @{
                    "Name" = "Free Virtual Memory"
                    "Value" = "$freeVirtualMemoryGB GB"
                }
                $systemInfo["Memory Status"] += @{
                    "Name" = "Used Virtual Memory"
                    "Value" = "$usedVirtualMemoryGB GB ($virtualMemoryUsagePercent%)"
                }
            } catch {
                $systemInfo["Memory Status"] += @{
                    "Name" = "Error"
                    "Value" = "Could not retrieve memory information: $($_.Exception.Message)"
                }
            }

            # Disk information
            try {
                $disks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
                $diskCount = 0

                foreach ($disk in $disks) {
                    $diskCount++
                    $diskSizeGB = [math]::Round($disk.Size / 1GB, 2)
                    $diskFreeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                    $diskUsedSpaceGB = [math]::Round($diskSizeGB - $diskFreeSpaceGB, 2)
                    $diskUsagePercent = [math]::Round(($diskUsedSpaceGB / $diskSizeGB) * 100, 1)

                    $systemInfo["Disk Information"] += @{
                        "Name" = "Drive $($disk.DeviceID)"
                        "Value" = "$($disk.VolumeName) - $diskSizeGB GB total, $diskFreeSpaceGB GB free ($diskUsagePercent% used)"
                    }
                }

                if ($diskCount -eq 0) {
                    $systemInfo["Disk Information"] += @{
                        "Name" = "Disks"
                        "Value" = "No fixed disks found"
                    }
                }
            } catch {
                $systemInfo["Disk Information"] += @{
                    "Name" = "Error"
                    "Value" = "Could not retrieve disk information: $($_.Exception.Message)"
                }
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="system-info-container">
                <div class="row">
"@

            # Process each category
            foreach ($category in $systemInfo.Keys) {
                $items = $systemInfo[$category]
                if ($items.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $htmlOutput += @"
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">$category</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <tbody>
"@

                    foreach ($item in $items) {
                        $name = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                        $value = [System.Web.HttpUtility]::HtmlEncode($item.Value)

                        $htmlOutput += @"
                                            <tr>
                                                <td style="width: 40%; font-weight: 500;">$name</td>
                                                <td style="word-break: break-word;">$value</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "System Information:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $systemInfo.Keys) {
                $items = $systemInfo[$category]
                if ($items.Count -gt 0) {
                    $textOutput += "`n$category:`n"
                    $textOutput += "-" * 30 + "`n"

                    foreach ($item in $items) {
                        $textOutput += "{0,-25} {1}`n" -f $item.Name + ":", $item.Value
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                try:
                    # Collect system information
                    system_info = [
                        {'key': 'System', 'value': platform.system()},
                        {'key': 'Node', 'value': platform.node()},
                        {'key': 'Release', 'value': platform.release()},
                        {'key': 'Version', 'value': platform.version()},
                        {'key': 'Machine', 'value': platform.machine()},
                        {'key': 'Processor', 'value': platform.processor()}
                    ]

                    # Format the output
                    output = self.format_output("System Information", system_info, is_table=False)
                    return output['html'].encode()
                except Exception as e:
                    # Fallback with minimal information if platform module fails
                    error_info = f"""
                    <div class="card">
                        <div class="card-header bg-danger text-white">
                            <h5 class="mb-0">System Information Error</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-danger">
                                <strong>Error:</strong> {html.escape(str(e))}
                            </div>
                            <p><strong>System:</strong> Windows (assumed)</p>
                            <p><strong>Note:</strong> Error occurred while collecting system information</p>
                        </div>
                    </div>
                    """
                    return error_info.encode()
        else:
            # For terminal display, use the original method
            try:
                # Collect system information
                system_info = [
                    {'key': 'System', 'value': platform.system()},
                    {'key': 'Node', 'value': platform.node()},
                    {'key': 'Release', 'value': platform.release()},
                    {'key': 'Version', 'value': platform.version()},
                    {'key': 'Machine', 'value': platform.machine()},
                    {'key': 'Processor', 'value': platform.processor()}
                ]

                # Format the output
                output = self.format_output("System Information", system_info, is_table=False)
                return output['text'].encode()
            except Exception as e:
                # Fallback with minimal information if platform module fails
                error_info = f"""
System Information (Error):
--------------------------
Error:      {str(e)}
System:     Windows (assumed)
Note:       Error occurred while collecting system information
"""
                return error_info.encode()

    def get_os_info(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Create a function to safely get WMI data
            function Get-SafeWmiData {
                param (
                    [string]$Class,
                    [string]$Property = "*"
                )

                try {
                    Get-WmiObject -Class $Class -Property $Property -ErrorAction Stop
                } catch {
                    Write-Output "Error: $($_.Exception.Message)"
                    return $null
                }
            }

            # Get OS information from multiple sources
            $osInfo = @{
                "Basic Information" = @()
                "System Details" = @()
                "Hardware" = @()
                "Memory" = @()
                "Network" = @()
            }

            # Get basic OS info
            $os = Get-SafeWmiData -Class "Win32_OperatingSystem"
            if ($os) {
                $osInfo["Basic Information"] += @{
                    "Name" = "OS Name"
                    "Value" = $os.Caption
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Version"
                    "Value" = $os.Version
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Build Number"
                    "Value" = $os.BuildNumber
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Architecture"
                    "Value" = $os.OSArchitecture
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Manufacturer"
                    "Value" = $os.Manufacturer
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Install Date"
                    "Value" = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate).ToString("yyyy-MM-dd HH:mm:ss")
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "Last Boot Time"
                    "Value" = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss")
                }
                $osInfo["Basic Information"] += @{
                    "Name" = "System Directory"
                    "Value" = $os.SystemDirectory
                }

                # Memory information
                $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                $freeMemGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                $usedMemGB = [math]::Round($totalMemGB - $freeMemGB, 2)
                $memUsagePercent = [math]::Round(($usedMemGB / $totalMemGB) * 100, 1)

                $osInfo["Memory"] += @{
                    "Name" = "Total Physical Memory"
                    "Value" = "$totalMemGB GB"
                }
                $osInfo["Memory"] += @{
                    "Name" = "Free Physical Memory"
                    "Value" = "$freeMemGB GB"
                }
                $osInfo["Memory"] += @{
                    "Name" = "Used Physical Memory"
                    "Value" = "$usedMemGB GB ($memUsagePercent%)"
                }

                $totalVirtMemGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 2)
                $freeVirtMemGB = [math]::Round($os.FreeVirtualMemory / 1MB, 2)
                $usedVirtMemGB = [math]::Round($totalVirtMemGB - $freeVirtMemGB, 2)
                $virtMemUsagePercent = [math]::Round(($usedVirtMemGB / $totalVirtMemGB) * 100, 1)

                $osInfo["Memory"] += @{
                    "Name" = "Total Virtual Memory"
                    "Value" = "$totalVirtMemGB GB"
                }
                $osInfo["Memory"] += @{
                    "Name" = "Free Virtual Memory"
                    "Value" = "$freeVirtMemGB GB"
                }
                $osInfo["Memory"] += @{
                    "Name" = "Used Virtual Memory"
                    "Value" = "$usedVirtMemGB GB ($virtMemUsagePercent%)"
                }
            }

            # Get computer system info
            $cs = Get-SafeWmiData -Class "Win32_ComputerSystem"
            if ($cs) {
                $osInfo["System Details"] += @{
                    "Name" = "Computer Name"
                    "Value" = $cs.Name
                }
                $osInfo["System Details"] += @{
                    "Name" = "Domain"
                    "Value" = $cs.Domain
                }
                $osInfo["System Details"] += @{
                    "Name" = "Manufacturer"
                    "Value" = $cs.Manufacturer
                }
                $osInfo["System Details"] += @{
                    "Name" = "Model"
                    "Value" = $cs.Model
                }
                $osInfo["System Details"] += @{
                    "Name" = "System Type"
                    "Value" = $cs.SystemType
                }
                $osInfo["System Details"] += @{
                    "Name" = "System Family"
                    "Value" = $cs.SystemFamily
                }
            }

            # Get processor info
            $cpu = Get-SafeWmiData -Class "Win32_Processor"
            if ($cpu) {
                $osInfo["Hardware"] += @{
                    "Name" = "Processor"
                    "Value" = $cpu.Name
                }
                $osInfo["Hardware"] += @{
                    "Name" = "Cores"
                    "Value" = "$($cpu.NumberOfCores) (Physical), $($cpu.NumberOfLogicalProcessors) (Logical)"
                }
                $osInfo["Hardware"] += @{
                    "Name" = "Max Clock Speed"
                    "Value" = "$($cpu.MaxClockSpeed) MHz"
                }
                $osInfo["Hardware"] += @{
                    "Name" = "L2 Cache Size"
                    "Value" = "$($cpu.L2CacheSize) KB"
                }
                $osInfo["Hardware"] += @{
                    "Name" = "L3 Cache Size"
                    "Value" = "$($cpu.L3CacheSize) KB"
                }
            }

            # Get BIOS info
            $bios = Get-SafeWmiData -Class "Win32_BIOS"
            if ($bios) {
                $osInfo["Hardware"] += @{
                    "Name" = "BIOS Manufacturer"
                    "Value" = $bios.Manufacturer
                }
                $osInfo["Hardware"] += @{
                    "Name" = "BIOS Version"
                    "Value" = $bios.SMBIOSBIOSVersion
                }
                $osInfo["Hardware"] += @{
                    "Name" = "BIOS Release Date"
                    "Value" = [System.Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate).ToString("yyyy-MM-dd")
                }
            }

            # Get network adapter configuration
            $nics = Get-SafeWmiData -Class "Win32_NetworkAdapterConfiguration" | Where-Object { $_.IPEnabled -eq $true }
            if ($nics) {
                foreach ($nic in $nics) {
                    $osInfo["Network"] += @{
                        "Name" = "Network Adapter"
                        "Value" = $nic.Description
                    }
                    $osInfo["Network"] += @{
                        "Name" = "IP Address(es)"
                        "Value" = $nic.IPAddress -join ", "
                    }
                    $osInfo["Network"] += @{
                        "Name" = "Subnet Mask"
                        "Value" = $nic.IPSubnet -join ", "
                    }
                    $osInfo["Network"] += @{
                        "Name" = "Default Gateway"
                        "Value" = $nic.DefaultIPGateway -join ", "
                    }
                    $osInfo["Network"] += @{
                        "Name" = "DNS Servers"
                        "Value" = $nic.DNSServerSearchOrder -join ", "
                    }
                    $osInfo["Network"] += @{
                        "Name" = "MAC Address"
                        "Value" = $nic.MACAddress
                    }
                    $osInfo["Network"] += @{
                        "Name" = "DHCP Enabled"
                        "Value" = $nic.DHCPEnabled
                    }
                }
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="os-info-container">
                <div class="row">
"@

            # Process each category
            foreach ($category in $osInfo.Keys) {
                $items = $osInfo[$category]
                if ($items.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $htmlOutput += @"
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">$category</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <tbody>
"@

                    foreach ($item in $items) {
                        $name = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                        $value = [System.Web.HttpUtility]::HtmlEncode($item.Value)

                        $htmlOutput += @"
                                            <tr>
                                                <td style="width: 40%; font-weight: 500;">$name</td>
                                                <td style="word-break: break-word;">$value</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Operating System Details:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $osInfo.Keys) {
                $items = $osInfo[$category]
                if ($items.Count -gt 0) {
                    $textOutput += "`n$category:`n"
                    $textOutput += "-" * 30 + "`n"

                    foreach ($item in $items) {
                        $textOutput += "{0,-25} {1}`n" -f $item.Name + ":", $item.Value
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                info_table = "Operating System Details:\n"
                info_table += "-" * 50 + "\n"

                try:
                    # Try to get OS info using WMI
                    os_data_list = list(c.Win32_OperatingSystem())

                    if os_data_list:
                        for os_data in os_data_list:
                            info_table += f"OS Name:      {os_data.Caption}\n"
                            info_table += f"Version:      {os_data.Version}\n"
                            info_table += f"Manufacturer: {os_data.Manufacturer}\n"
                    else:
                        # Fallback to platform module if WMI returns no data
                        info_table += f"OS Name:      {platform.system()} {platform.release()}\n"
                        info_table += f"Version:      {platform.version()}\n"
                        info_table += f"Manufacturer: Microsoft Corporation\n"
                except Exception as e:
                    # If WMI fails, use platform module as fallback
                    info_table += f"Error accessing WMI: {str(e)}\n"
                    info_table += f"Using fallback method:\n"
                    info_table += f"OS Name:      {platform.system()} {platform.release()}\n"
                    info_table += f"Version:      {platform.version()}\n"
                    info_table += f"Architecture: {platform.machine()}\n"

                # Format as HTML
                html_output = f"""
                <div class="os-info-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Operating System Details</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(info_table)}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            info_table = "Operating System Details:\n"
            info_table += "-" * 50 + "\n"

            try:
                # Try to get OS info using WMI
                os_data_list = list(c.Win32_OperatingSystem())

                if os_data_list:
                    for os_data in os_data_list:
                        info_table += f"OS Name:      {os_data.Caption}\n"
                        info_table += f"Version:      {os_data.Version}\n"
                        info_table += f"Manufacturer: {os_data.Manufacturer}\n"
                else:
                    # Fallback to platform module if WMI returns no data
                    info_table += f"OS Name:      {platform.system()} {platform.release()}\n"
                    info_table += f"Version:      {platform.version()}\n"
                    info_table += f"Manufacturer: Microsoft Corporation\n"
            except Exception as e:
                # If WMI fails, use platform module as fallback
                info_table += f"Error accessing WMI: {str(e)}\n"
                info_table += f"Using fallback method:\n"
                info_table += f"OS Name:      {platform.system()} {platform.release()}\n"
                info_table += f"Version:      {platform.version()}\n"
                info_table += f"Architecture: {platform.machine()}\n"

            return info_table.encode()

    def get_amsi_providers(self):
        table = "AMSI Providers:\n"
        table += "-" * 70 + "\n"
        command = """
        $ErrorActionPreference = 'Stop'

        Write-Output "Method 1 - Registry Check (COM Objects):"
        Write-Output "-" * 50

        try {
            $clsids = Get-ChildItem 'HKLM:\\SOFTWARE\\Classes\\CLSID' -ErrorAction Stop |
                Where-Object {
                    $clsid = $_.PSChildName
                    $interfaces = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Classes\\CLSID\\$clsid\\Implemented Categories" -ErrorAction SilentlyContinue
                    $interfaces -match "AMSI"
                }
            foreach ($cls in $clsids) {
                $name = (Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Classes\\CLSID\\$($cls.PSChildName)" -ErrorAction SilentlyContinue).'(Default)'
                "CLSID: $($cls.PSChildName)"
                "Name : $name"
                "-" * 30
            }
        } catch {
            "Unable to query COM objects (requires elevation)"
        }

        Write-Output "`nMethod 2 - Direct AMSI Provider Check:"
        Write-Output "-" * 50
        try {
            if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers') {
                Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' | ForEach-Object {
                    "Provider ID: $($_.PSChildName)"
                    $details = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                    foreach($prop in $details.PSObject.Properties) {
                        if ($prop.Name -notmatch '^PS') {
                            "  $($prop.Name): $($prop.Value)"
                        }
                    }
                    "-" * 30
                }
            } else {
                "AMSI providers registry path not found"
            }
        } catch {
            "Unable to query AMSI providers directly (requires elevation)"
        }
        """
        output = run_powershell_command(command)
        if not output:
            output = "No AMSI providers detected or insufficient permissions to query them"
        return (table + output).encode()

    def get_registered_antivirus(self):
        table = "Installed Antivirus Products:\n"
        table += "-" * 70 + "\n"
        command = """
        Write-Output "Method 1 - Windows Security Center:"
        Write-Output "-" * 50
        try {
            Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
            ForEach-Object {
                "Product: $($_.displayName)"
                "Path   : $($_.pathToSignedReportingExe)"
                "Status : $($_.productState)"
                "-" * 30
            }
        } catch {
            "Unable to query Security Center"
        }

        Write-Output "`nMethod 2 - Windows Defender Status:"
        Write-Output "-" * 50
        try {
            Get-Service -Name WinDefend | ForEach-Object {
                "Windows Defender Service Status: $($_.Status)"
            }
        } catch {
            "Unable to query Windows Defender service"
        }

        Write-Output "`nMethod 3 - Installed Security Software:"
        Write-Output "-" * 50
        Get-WmiObject -Class Win32_Product | Where-Object {
            $_.Name -match 'antivirus|security|defender|mcafee|norton|avg|avast|kaspersky|bitdefender|trend micro|eset'
        } | ForEach-Object {
            "Name   : $($_.Name)"
            "Vendor : $($_.Vendor)"
            "Version: $($_.Version)"
            "-" * 30
        }
        """
        output = run_powershell_command(command)
        return (table + (output or "No antivirus products detected")).encode()

    def get_audit_policy(self):
        table = "Audit Policy:\n"
        table += "-" * 70 + "\n"
        command = """
        # Create a function to format output as a table
        function Format-TableOutput {
            param (
                [string]$Title,
                [string]$Subtitle = "",
                [scriptblock]$ContentBlock
            )

            Write-Output $Title
            Write-Output ("-" * 70)

            if ($Subtitle) {
                Write-Output $Subtitle
                Write-Output ("-" * 50)
            }

            try {
                & $ContentBlock
            }
            catch {
                Write-Output "Error: $($_.Exception.Message)"
            }

            Write-Output ""
        }

        # Windows Audit Policy Settings
        Format-TableOutput -Title "Windows Audit Policy Settings" {
            # Method 1: Get detailed audit policy using auditpol.exe
            Format-TableOutput -Title "1. Detailed Audit Policy Categories" {
                try {
                    $auditpol = & auditpol.exe /get /category:* /r | ConvertFrom-Csv
                    if ($auditpol) {
                        $categories = $auditpol | Group-Object -Property "Category/Subcategory"

                        foreach ($category in $categories) {
                            Write-Output "`n$($category.Name)"
                            Write-Output "-" * 50

                            foreach ($item in $category.Group) {
                                $setting = $item."Inclusion Setting"
                                $settingDisplay = if ($setting -eq "No Auditing") { "Disabled" } else { $setting }
                                "{0,-40} : {1}" -f $item."Subcategory", $settingDisplay
                            }
                        }
                    } else {
                        "Unable to retrieve detailed audit policy (requires elevation)"
                    }
                } catch {
                    "Error retrieving detailed audit policy: $($_.Exception.Message)"
                }
            }

            # Method 2: Registry Audit Settings
            Format-TableOutput -Title "2. Registry Audit Settings" {
                $regPaths = @(
                    @{
                        Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit'
                        Description = 'System Audit Policies'
                    },
                    @{
                        Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
                        Description = 'LSA Audit Settings'
                    },
                    @{
                        Path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security'
                        Description = 'Security Event Log Configuration'
                    }
                )

                foreach ($pathInfo in $regPaths) {
                    $path = $pathInfo.Path
                    if (Test-Path $path) {
                        Write-Output "`n$($pathInfo.Description) ($path)"
                        Write-Output "-" * 50

                        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                        if ($props) {
                            $auditProps = $props.PSObject.Properties | Where-Object {
                                $_.Name -match 'audit|Audit|log|Log' -and
                                $_.Name -notmatch '^PS'
                            }

                            if ($auditProps) {
                                foreach ($prop in $auditProps) {
                                    "{0,-30} : {1}" -f $prop.Name, $prop.Value
                                }
                            } else {
                                "No audit-related properties found"
                            }
                        } else {
                            "Unable to read properties"
                        }
                    }
                }
            }

            # Method 3: Process Command Line Auditing
            Format-TableOutput -Title "3. Process Command Line Auditing" {
                try {
                    $processPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled'
                    if (Test-Path $processPath) {
                        $value = Get-ItemProperty -Path $processPath -ErrorAction SilentlyContinue
                        $enabled = if ($value.'(default)' -eq 1) { "Enabled" } else { "Disabled" }
                        "Command line auditing: $enabled"
                    } else {
                        "Command line auditing registry key not found (default: Disabled)"
                    }

                    # Check if process creation events are being audited
                    $processAudit = & auditpol.exe /get /subcategory:"Process Creation" /r | ConvertFrom-Csv
                    if ($processAudit) {
                        $setting = $processAudit."Inclusion Setting"
                        "Process creation auditing: $setting"
                    }
                } catch {
                    "Unable to determine process auditing settings: $($_.Exception.Message)"
                }
            }

            # Method 4: Security Event Log Configuration
            Format-TableOutput -Title "4. Security Event Log Configuration" {
                try {
                    $logConfig = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
                    if ($logConfig) {
                        "Log Enabled        : $($logConfig.IsEnabled)"
                        "Log Full Behavior  : $($logConfig.LogMode)"
                        "Maximum Size (MB)  : $([math]::Round($logConfig.MaximumSizeInBytes / 1MB, 2))"
                        "Current Size (MB)  : $([math]::Round($logConfig.FileSize / 1MB, 2))"
                        "Records Count      : $($logConfig.RecordCount)"
                        "Retention Days     : $($logConfig.LogFilePath)"
                    } else {
                        "Unable to access Security event log configuration (requires elevation)"
                    }
                } catch {
                    "Unable to read security event log settings: $($_.Exception.Message)"
                }
            }
        }
        """
        output = run_powershell_command(command, timeout=60)  # Increase timeout for this command
        if not output:
            output = "No audit policy information available (requires elevated privileges)"

        # Create HTML output for web display
        html_output = f"""
        <div class="audit-policy-container">
            <h3 class="section-title">Windows Audit Policy</h3>
            <div class="audit-content">
                <pre class="audit-output">{html.escape(output)}</pre>
            </div>
        </div>
        """

        # Return either HTML for web display or plain text for terminal
        if 'web_display' in self.__dict__ and self.web_display:
            return html_output.encode()
        else:
            return (table + output).encode()

    def get_auto_run_executables(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Define registry locations to check
            $registryLocations = @(
                @{ Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'; Name = 'HKLM Run' },
                @{ Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; Name = 'HKLM RunOnce' },
                @{ Path = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'; Name = 'HKCU Run' },
                @{ Path = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; Name = 'HKCU RunOnce' },
                @{ Path = 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'; Name = 'HKLM Run (32-bit)' }
            )

            # Define startup folders to check
            $startupFolders = @(
                @{ Path = [System.Environment]::GetFolderPath('Startup'); Name = 'User Startup' },
                @{ Path = [System.Environment]::GetFolderPath('CommonStartup'); Name = 'Common Startup' }
            )

            # Create a hashtable to store all auto-run entries
            $autoRunEntries = @{}

            # Process registry locations
            foreach ($location in $registryLocations) {
                $entries = @()

                if (Test-Path $location.Path) {
                    $items = Get-ItemProperty -Path $location.Path -ErrorAction SilentlyContinue |
                             Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider,PSDrive

                    if ($items -and $items.PSObject.Properties.Count -gt 0) {
                        foreach ($prop in $items.PSObject.Properties) {
                            $entries += @{
                                Name = $prop.Name
                                Path = $prop.Value
                                Type = "Registry"
                                Modified = $null
                                Size = $null
                            }
                        }
                    }
                }

                $autoRunEntries[$location.Name] = @{
                    Path = $location.Path
                    Entries = $entries
                }
            }

            # Process startup folders
            foreach ($folder in $startupFolders) {
                $entries = @()

                if (Test-Path $folder.Path) {
                    $items = Get-ChildItem -Path $folder.Path -ErrorAction SilentlyContinue

                    if ($items) {
                        foreach ($item in $items) {
                            $entries += @{
                                Name = $item.Name
                                Path = $item.FullName
                                Type = if ($item.PSIsContainer) { "Folder" } else { $item.Extension }
                                Modified = $item.LastWriteTime
                                Size = if ($item.PSIsContainer) { $null } else { $item.Length }
                            }
                        }
                    }
                }

                $autoRunEntries[$folder.Name] = @{
                    Path = $folder.Path
                    Entries = $entries
                }
            }

            # Check scheduled tasks that run at startup
            $entries = @()
            try {
                $startupTasks = Get-ScheduledTask | Where-Object {
                    $_.Triggers | Where-Object {
                        $_ -is [Microsoft.Management.Infrastructure.CimInstance] -and
                        $_.CimClass.CimClassName -match 'BootTrigger|LogonTrigger'
                    }
                } | Where-Object { $_.State -ne 'Disabled' }

                if ($startupTasks) {
                    foreach ($task in $startupTasks) {
                        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                        $entries += @{
                            Name = $task.TaskName
                            Path = $task.TaskPath
                            Type = "Scheduled Task"
                            Modified = $taskInfo.LastRunTime
                            Size = $null
                        }
                    }
                }
            } catch {
                $entries += @{
                    Name = "Error"
                    Path = "Could not retrieve scheduled tasks: $($_.Exception.Message)"
                    Type = "Error"
                    Modified = $null
                    Size = $null
                }
            }

            $autoRunEntries["Startup Tasks"] = @{
                Path = "Task Scheduler"
                Entries = $entries
            }

            # Create HTML output with cards for each location
            $htmlOutput = @"
            <div class="auto-run-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="auto-run-search" placeholder="Search auto-run entries..." onkeyup="filterAutoRun()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearAutoRunSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by name or path</div>
                </div>

                <script>
                function filterAutoRun() {
                    const searchText = document.getElementById('auto-run-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.auto-run-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const name = row.querySelector('.auto-run-name').textContent.toLowerCase();
                        const path = row.querySelector('.auto-run-path').textContent.toLowerCase();

                        if (searchText === '' || name.includes(searchText) || path.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.auto-run-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.auto-run-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });
                }

                function clearAutoRunSearch() {
                    document.getElementById('auto-run-search').value = '';
                    filterAutoRun();
                }
                </script>

                <div class="row">
"@

            # Process each location
            foreach ($locationName in $autoRunEntries.Keys) {
                $locationInfo = $autoRunEntries[$locationName]
                $entries = $locationInfo.Entries
                $locationPath = $locationInfo.Path

                $locationId = $locationName.Replace(" ", "-").Replace("(", "").Replace(")", "").Replace(":", "").ToLower()

                # Choose card color based on location type
                $cardColor = switch -Wildcard ($locationName) {
                    "HKLM*" { "bg-danger" }
                    "HKCU*" { "bg-warning" }
                    "*Startup*" { "bg-success" }
                    "Startup Tasks" { "bg-info" }
                    default { "bg-primary" }
                }

                $htmlOutput += @"
                    <div class="col-md-6 mb-4 auto-run-category" id="location-$locationId">
                        <div class="card h-100">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">$locationName</h5>
                                    <span class="badge bg-light text-dark">$($entries.Count) items</span>
                                </div>
                                <small>$([System.Web.HttpUtility]::HtmlEncode($locationPath))</small>
                            </div>
                            <div class="card-body p-0">
"@

                if ($entries.Count -eq 0) {
                    $htmlOutput += @"
                                <div class="alert alert-info m-3">
                                    <i class="fas fa-info-circle me-2"></i>
                                    No auto-run entries found in this location.
                                </div>
"@
                } else {
                    $htmlOutput += @"
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Name</th>
                                                <th>Path</th>
                                                <th>Type</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                    foreach ($entry in $entries) {
                        $name = [System.Web.HttpUtility]::HtmlEncode($entry.Name)
                        $path = [System.Web.HttpUtility]::HtmlEncode($entry.Path)
                        $type = [System.Web.HttpUtility]::HtmlEncode($entry.Type)

                        # Choose icon based on type
                        $icon = switch -Wildcard ($type) {
                            "Registry" { '<i class="fas fa-cog text-primary"></i>' }
                            "Scheduled Task" { '<i class="fas fa-clock text-info"></i>' }
                            "Folder" { '<i class="fas fa-folder text-warning"></i>' }
                            "*.exe" { '<i class="fas fa-file-code text-danger"></i>' }
                            "*.dll" { '<i class="fas fa-file-alt text-secondary"></i>' }
                            "*.lnk" { '<i class="fas fa-link text-success"></i>' }
                            "*.bat" { '<i class="fas fa-terminal text-dark"></i>' }
                            "*.vbs" { '<i class="fas fa-file-code text-primary"></i>' }
                            "Error" { '<i class="fas fa-exclamation-triangle text-danger"></i>' }
                            default { '<i class="fas fa-file text-muted"></i>' }
                        }

                        $htmlOutput += @"
                                            <tr class="auto-run-row">
                                                <td class="auto-run-name">$icon <span style="margin-left: 5px;">$name</span></td>
                                                <td class="auto-run-path" style="word-break: break-word;">$path</td>
                                                <td>$type</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
"@
                }

                $htmlOutput += @"
                            </div>
                        </div>
                    </div>
"@
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Auto-Run Executables:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($locationName in $autoRunEntries.Keys) {
                $locationInfo = $autoRunEntries[$locationName]
                $entries = $locationInfo.Entries
                $locationPath = $locationInfo.Path

                $textOutput += "`n$locationName ($locationPath):`n"
                $textOutput += "-" * 50 + "`n"

                if ($entries.Count -eq 0) {
                    $textOutput += "No entries found`n"
                } else {
                    foreach ($entry in $entries) {
                        $textOutput += "Name    : $($entry.Name)`n"
                        $textOutput += "Path    : $($entry.Path)`n"
                        $textOutput += "Type    : $($entry.Type)`n"

                        if ($entry.Modified) {
                            $textOutput += "Modified: $($entry.Modified)`n"
                        }

                        $textOutput += "-" * 50 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "Auto-Run Executables:\n"
                table += "-" * 70 + "\n"
                command = """
                $locations = @(
                    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
                )

                foreach ($location in $locations) {
                    if (Test-Path $location) {
                        Write-Output "`nLocation: $location"
                        Write-Output "-" * 50

                        $items = Get-ItemProperty -Path $location |
                                Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider,PSDrive

                        if ($items.PSObject.Properties.Count -gt 0) {
                            # Calculate max name length for alignment
                            $maxNameLength = ($items.PSObject.Properties | Measure-Object -Maximum -Property Name).Maximum
                            $maxNameLength = [Math]::Max($maxNameLength.Length, 20)  # minimum 20 chars

                            foreach ($prop in $items.PSObject.Properties) {
                                $namePadded = $prop.Name.PadRight($maxNameLength)
                                Write-Output "Name: $namePadded"
                                Write-Output "Path: $($prop.Value)"
                                Write-Output ("-" * 50)
                            }
                        } else {
                            Write-Output "No entries found"
                            Write-Output ("-" * 50)
                        }
                    }
                }

                Write-Output "`nStartup Folders:"
                Write-Output "-" * 50

                $userStartup = [System.Environment]::GetFolderPath('Startup')
                $commonStartup = [System.Environment]::GetFolderPath('CommonStartup')

                Write-Output "User Startup ($userStartup):"
                $userItems = Get-ChildItem -Path $userStartup -ErrorAction SilentlyContinue
                if ($userItems) {
                    foreach ($item in $userItems) {
                        Write-Output "Name    : $($item.Name)"
                        Write-Output "Type    : $($item.Extension)"
                        Write-Output "Modified: $($item.LastWriteTime)"
                        Write-Output ("-" * 50)
                    }
                } else {
                    Write-Output "No items found"
                    Write-Output ("-" * 50)
                }

                Write-Output "`nCommon Startup ($commonStartup):"
                $commonItems = Get-ChildItem -Path $commonStartup -ErrorAction SilentlyContinue
                if ($commonItems) {
                    foreach ($item in $commonItems) {
                        Write-Output "Name    : $($item.Name)"
                        Write-Output "Type    : $($item.Extension)"
                        Write-Output "Modified: $($item.LastWriteTime)"
                        Write-Output ("-" * 50)
                    }
                } else {
                    Write-Output "No items found"
                    Write-Output ("-" * 50)
                }
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="auto-run-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Auto-Run Executables</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(output or "No auto-run executables found")}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "Auto-Run Executables:\n"
            table += "-" * 70 + "\n"
            command = """
            $locations = @(
                'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            )

            foreach ($location in $locations) {
                if (Test-Path $location) {
                    Write-Output "`nLocation: $location"
                    Write-Output "-" * 50

                    $items = Get-ItemProperty -Path $location |
                            Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider,PSDrive

                    if ($items.PSObject.Properties.Count -gt 0) {
                        # Calculate max name length for alignment
                        $maxNameLength = ($items.PSObject.Properties | Measure-Object -Maximum -Property Name).Maximum
                        $maxNameLength = [Math]::Max($maxNameLength.Length, 20)  # minimum 20 chars

                        foreach ($prop in $items.PSObject.Properties) {
                            $namePadded = $prop.Name.PadRight($maxNameLength)
                            Write-Output "Name: $namePadded"
                            Write-Output "Path: $($prop.Value)"
                            Write-Output ("-" * 50)
                        }
                    } else {
                        Write-Output "No entries found"
                        Write-Output ("-" * 50)
                    }
                }
            }

            Write-Output "`nStartup Folders:"
            Write-Output "-" * 50

            $userStartup = [System.Environment]::GetFolderPath('Startup')
            $commonStartup = [System.Environment]::GetFolderPath('CommonStartup')

            Write-Output "User Startup ($userStartup):"
            $userItems = Get-ChildItem -Path $userStartup -ErrorAction SilentlyContinue
            if ($userItems) {
                foreach ($item in $userItems) {
                    Write-Output "Name    : $($item.Name)"
                    Write-Output "Type    : $($item.Extension)"
                    Write-Output "Modified: $($item.LastWriteTime)"
                    Write-Output ("-" * 50)
                }
            } else {
                Write-Output "No items found"
                Write-Output ("-" * 50)
            }

            Write-Output "`nCommon Startup ($commonStartup):"
            $commonItems = Get-ChildItem -Path $commonStartup -ErrorAction SilentlyContinue
            if ($commonItems) {
                foreach ($item in $commonItems) {
                    Write-Output "Name    : $($item.Name)"
                    Write-Output "Type    : $($item.Extension)"
                    Write-Output "Modified: $($item.LastWriteTime)"
                    Write-Output ("-" * 50)
                }
            } else {
                Write-Output "No items found"
                Write-Output ("-" * 50)
            }
            """
            output = run_powershell_command(command)
            return (table + (output or "No auto-run executables found")).encode()

    def get_firewall_rules(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get firewall rules
            $firewallRules = @{
                "Inbound Allow" = @()
                "Inbound Block" = @()
                "Outbound Allow" = @()
                "Outbound Block" = @()
            }

            try {
                # Get all enabled firewall rules
                $rules = Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' } |
                         Select-Object DisplayName, Description, Direction, Action, Profile,
                                       @{Name="Program"; Expression={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Program}},
                                       @{Name="Protocol"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).Protocol}},
                                       @{Name="LocalPort"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},
                                       @{Name="RemotePort"; Expression={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).RemotePort}},
                                       @{Name="RemoteAddress"; Expression={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}}

                # Categorize rules
                foreach ($rule in $rules) {
                    $category = "$($rule.Direction) $($rule.Action)"

                    switch ($category) {
                        "Inbound Allow" { $firewallRules["Inbound Allow"] += $rule }
                        "Inbound Block" { $firewallRules["Inbound Block"] += $rule }
                        "Outbound Allow" { $firewallRules["Outbound Allow"] += $rule }
                        "Outbound Block" { $firewallRules["Outbound Block"] += $rule }
                    }
                }
            } catch {
                $firewallRules["Error"] = @(@{
                    DisplayName = "Error"
                    Description = "Could not retrieve firewall rules: $($_.Exception.Message)"
                })
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="firewall-rules-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="firewall-rule-search" placeholder="Search firewall rules..." onkeyup="filterFirewallRules()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearFirewallSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by name, program, or port</div>
                </div>

                <script>
                function filterFirewallRules() {
                    const searchText = document.getElementById('firewall-rule-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.firewall-rule-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const name = row.querySelector('.rule-name').textContent.toLowerCase();
                        const program = row.querySelector('.rule-program')?.textContent.toLowerCase() || '';
                        const ports = row.querySelector('.rule-ports')?.textContent.toLowerCase() || '';

                        if (searchText === '' || name.includes(searchText) || program.includes(searchText) || ports.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.firewall-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.firewall-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });
                }

                function clearFirewallSearch() {
                    document.getElementById('firewall-rule-search').value = '';
                    filterFirewallRules();
                }
                </script>

                <div class="row">
"@

            # Process each category
            foreach ($category in $firewallRules.Keys) {
                $rules = $firewallRules[$category]

                if ($rules.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Inbound Allow" { "bg-success" }
                        "Inbound Block" { "bg-danger" }
                        "Outbound Allow" { "bg-info" }
                        "Outbound Block" { "bg-warning" }
                        "Error" { "bg-danger" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-md-12 mb-4 firewall-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">$category</h5>
                                    <span class="badge bg-light text-dark">$($rules.Count) rules</span>
                                </div>
                            </div>
                            <div class="card-body p-0">
"@

                    if ($category -eq "Error") {
                        $htmlOutput += @"
                                <div class="alert alert-danger m-3">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    $([System.Web.HttpUtility]::HtmlEncode($rules[0].Description))
                                </div>
"@
                    } else {
                        $htmlOutput += @"
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Rule Name</th>
                                                <th>Program</th>
                                                <th>Protocol</th>
                                                <th>Ports</th>
                                                <th>Profile</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                        foreach ($rule in $rules) {
                            $displayName = [System.Web.HttpUtility]::HtmlEncode($rule.DisplayName)
                            $program = [System.Web.HttpUtility]::HtmlEncode($rule.Program)
                            $protocol = [System.Web.HttpUtility]::HtmlEncode($rule.Protocol)
                            $localPort = [System.Web.HttpUtility]::HtmlEncode($rule.LocalPort)
                            $remotePort = [System.Web.HttpUtility]::HtmlEncode($rule.RemotePort)
                            $profile = [System.Web.HttpUtility]::HtmlEncode($rule.Profile)

                            # Format ports
                            $ports = ""
                            if ($localPort) { $ports += "Local: $localPort" }
                            if ($remotePort) {
                                if ($ports) { $ports += ", " }
                                $ports += "Remote: $remotePort"
                            }
                            if (-not $ports) { $ports = "Any" }

                            # Format program
                            if (-not $program) { $program = "Any" }

                            # Format protocol
                            if (-not $protocol) { $protocol = "Any" }

                            $htmlOutput += @"
                                            <tr class="firewall-rule-row">
                                                <td class="rule-name">$displayName</td>
                                                <td class="rule-program">$program</td>
                                                <td>$protocol</td>
                                                <td class="rule-ports">$ports</td>
                                                <td>$profile</td>
                                            </tr>
"@
                        }

                        $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
"@
                    }

                    $htmlOutput += @"
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Firewall Rules:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $firewallRules.Keys) {
                $rules = $firewallRules[$category]

                if ($rules.Count -gt 0) {
                    $textOutput += "`n$category ($($rules.Count) rules):`n"
                    $textOutput += "-" * 50 + "`n"

                    if ($category -eq "Error") {
                        $textOutput += "$($rules[0].Description)`n"
                    } else {
                        foreach ($rule in $rules) {
                            $textOutput += "Name    : $($rule.DisplayName)`n"
                            $textOutput += "Program : $($rule.Program -or 'Any')`n"
                            $textOutput += "Protocol: $($rule.Protocol -or 'Any')`n"

                            $ports = ""
                            if ($rule.LocalPort) { $ports += "Local: $($rule.LocalPort)" }
                            if ($rule.RemotePort) {
                                if ($ports) { $ports += ", " }
                                $ports += "Remote: $($rule.RemotePort)"
                            }
                            if (-not $ports) { $ports = "Any" }

                            $textOutput += "Ports   : $ports`n"
                            $textOutput += "Profile : $($rule.Profile)`n"
                            $textOutput += "-" * 50 + "`n"
                        }
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout for firewall rules

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                command = """
                Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} |
                Select-Object DisplayName, Direction, Action, Profile |
                Format-Table -AutoSize
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="firewall-rules-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Firewall Rules</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(output or "No firewall rules found")}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            command = """
            Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} |
            Select-Object DisplayName, Direction, Action, Profile |
            Format-Table -AutoSize
            """
            return run_powershell_command(command).encode()

    def get_windows_defender_settings(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Create a function to safely get data
            function Get-SafeData {
                param (
                    [scriptblock]$ScriptBlock,
                    [string]$ErrorMessage = "Unable to retrieve data"
                )

                try {
                    & $ScriptBlock
                } catch {
                    @{
                        "Error" = "$ErrorMessage`: $($_.Exception.Message)"
                    }
                }
            }

            # Get Windows Defender information
            $defenderInfo = @{
                "Service Status" = @()
                "Protection Status" = @()
                "Signature Information" = @()
                "Scan Information" = @()
                "Threat Detection" = @()
            }

            # Add custom CSS for Windows Defender display
            $customCSS = @"
            <style>
                .defender-card {
                    box-shadow: 0 2px 4px rgba(0,0,0,.1);
                    transition: all 0.3s ease;
                }
                .defender-card:hover {
                    box-shadow: 0 4px 8px rgba(0,0,0,.2);
                }
                .card-header {
                    font-weight: 600;
                }
                .status-badge {
                    padding: 0.35em 0.65em;
                    font-size: 0.9em;
                    font-weight: 600;
                    border-radius: 0.25rem;
                }
                .status-enabled {
                    background-color: #d1e7dd;
                    color: #0f5132;
                }
                .status-disabled {
                    background-color: #f8d7da;
                    color: #842029;
                }
                .table td {
                    vertical-align: middle;
                }
            </style>
"@

            # Get service status
            $defenderService = Get-SafeData -ScriptBlock {
                $service = Get-Service -Name WinDefend -ErrorAction Stop
                @{
                    "Service Name" = "Windows Defender"
                    "Status" = $service.Status.ToString()
                    "Start Type" = $service.StartType.ToString()
                    "Display Name" = $service.DisplayName
                    "Dependencies" = ($service.ServicesDependedOn | ForEach-Object { $_.Name }) -join ", "
                }
            } -ErrorMessage "Unable to retrieve service information"

            if ($defenderService -and -not $defenderService.ContainsKey("Error")) {
                foreach ($key in $defenderService.Keys) {
                    $defenderInfo["Service Status"] += @{
                        "Name" = $key
                        "Value" = $defenderService[$key]
                    }
                }
            } else {
                $defenderInfo["Service Status"] += @{
                    "Name" = "Error"
                    "Value" = if ($defenderService.ContainsKey("Error")) { $defenderService["Error"] } else { "Unknown error" }
                }
            }

            # Get protection status
            $mpStatus = Get-SafeData -ScriptBlock {
                Get-MpComputerStatus -ErrorAction Stop
            } -ErrorMessage "Unable to retrieve protection status"

            if ($mpStatus -and -not $mpStatus.ContainsKey("Error")) {
                # Protection status
                $protectionItems = @(
                    @{ Name = "Real-Time Protection"; Value = $mpStatus.RealTimeProtectionEnabled },
                    @{ Name = "IoAV Protection"; Value = $mpStatus.IoavProtectionEnabled },
                    @{ Name = "Antispyware"; Value = $mpStatus.AntispywareEnabled },
                    @{ Name = "Antivirus"; Value = $mpStatus.AntivirusEnabled },
                    @{ Name = "Behavior Monitor"; Value = $mpStatus.BehaviorMonitorEnabled },
                    @{ Name = "Network Inspection"; Value = $mpStatus.NISEnabled },
                    @{ Name = "On Access Protection"; Value = $mpStatus.OnAccessProtectionEnabled },
                    @{ Name = "Tamper Protection"; Value = $mpStatus.IsTamperProtected }
                )

                foreach ($item in $protectionItems) {
                    $value = if ($null -eq $item.Value) { "N/A" } else {
                        if ($item.Value -eq $true) {
                            "Enabled"
                        } elseif ($item.Value -eq $false) {
                            "Disabled"
                        } else {
                            $item.Value
                        }
                    }

                    $defenderInfo["Protection Status"] += @{
                        "Name" = $item.Name
                        "Value" = $value
                    }
                }

                # Signature information
                $signatureItems = @(
                    @{ Name = "Signature Last Updated"; Value = $mpStatus.AntivirusSignatureLastUpdated },
                    @{ Name = "Signature Age (Days)"; Value = $mpStatus.AntivirusSignatureAge },
                    @{ Name = "Signature Version"; Value = $mpStatus.AntivirusSignatureVersion },
                    @{ Name = "Engine Version"; Value = $mpStatus.AMEngineVersion },
                    @{ Name = "Antispyware Signature Version"; Value = $mpStatus.AntispywareSignatureVersion }
                )

                foreach ($item in $signatureItems) {
                    $defenderInfo["Signature Information"] += @{
                        "Name" = $item.Name
                        "Value" = if ($null -eq $item.Value) { "N/A" } else { $item.Value }
                    }
                }

                # Scan information
                $scanItems = @(
                    @{ Name = "Quick Scan Age (Days)"; Value = $mpStatus.QuickScanAge },
                    @{ Name = "Full Scan Age (Days)"; Value = $mpStatus.FullScanAge },
                    @{ Name = "Last Quick Scan Time"; Value = $mpStatus.QuickScanEndTime },
                    @{ Name = "Last Full Scan Time"; Value = $mpStatus.FullScanEndTime },
                    @{ Name = "Last Scan Source"; Value = $mpStatus.LastFullScanSource }
                )

                foreach ($item in $scanItems) {
                    $defenderInfo["Scan Information"] += @{
                        "Name" = $item.Name
                        "Value" = if ($null -eq $item.Value) { "N/A" } else { $item.Value }
                    }
                }

                # Threat detection
                $threatItems = @(
                    @{ Name = "Threats Detected"; Value = $mpStatus.ThreatCount },
                    @{ Name = "Potentially Unwanted Apps"; Value = $mpStatus.PUACount },
                    @{ Name = "Suspicious Activities Detected"; Value = $mpStatus.SuspiciousActivitiesDetected }
                )

                foreach ($item in $threatItems) {
                    $defenderInfo["Threat Detection"] += @{
                        "Name" = $item.Name
                        "Value" = if ($null -eq $item.Value) { "0" } else { $item.Value }
                    }
                }
            } else {
                $defenderInfo["Protection Status"] += @{
                    "Name" = "Error"
                    "Value" = if ($mpStatus.ContainsKey("Error")) { $mpStatus["Error"] } else { "Unknown error" }
                }
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            $customCSS
            <div class="defender-settings-container">
                <div class="alert alert-info mb-3">
                    <i class="fas fa-shield-alt me-2"></i>
                    Windows Defender Security Status Overview
                </div>
                <div class="row">

"@

            # Process each category
            foreach ($category in $defenderInfo.Keys) {
                $items = $defenderInfo[$category]
                if ($items.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Service Status" { "bg-primary" }
                        "Protection Status" { "bg-success" }
                        "Signature Information" { "bg-info" }
                        "Scan Information" { "bg-warning" }
                        "Threat Detection" { "bg-danger" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-lg-6 mb-4">
                        <div class="card defender-card h-100">
                            <div class="card-header $cardColor text-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0"><i class="fas fa-shield-alt me-2"></i>$category</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover align-middle mb-0">
                                        <tbody>
"@

                    foreach ($item in $items) {
                        $name = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                        $value = [System.Web.HttpUtility]::HtmlEncode($item.Value)

                        # Enhanced status badge styling
                        $valueDisplay = $value
                        if ($value -eq "Enabled") {
                            $valueDisplay = '<span class="status-badge status-enabled">Enabled</span>'
                        } elseif ($value -eq "Disabled") {
                            $valueDisplay = '<span class="status-badge status-disabled">Disabled</span>'
                        }

                        $htmlOutput += @"
                                            <tr>
                                                <td style="width: 40%;" class="fw-medium">$name</td>
                                                <td style="word-break: break-word;">$valueDisplay</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Windows Defender Settings:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $defenderInfo.Keys) {
                $items = $defenderInfo[$category]
                if ($items.Count -gt 0) {
                    $textOutput += "`n$category:`n"
                    $textOutput += "-" * 30 + "`n"

                    foreach ($item in $items) {
                        $textOutput += "{0,-30} : {1}`n" -f $item.Name, $item.Value
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "Windows Defender Settings:\n"
                table += "-" * 70 + "\n"
                command = """
                Write-Output "1. Service Status"
                Write-Output "-" * 50
                $defender = Get-Service -Name WinDefend
                "Service Name : Windows Defender"
                "Status      : $($defender.Status)"
                "Start Type  : $($defender.StartType)"

                Write-Output "`n2. Protection Status"
                Write-Output "-" * 50
                try {
                    $status = Get-MpComputerStatus
                    $protectionItems = @(
                        @{ Label = "Real-Time Protection Enabled"; Value = $status.RealTimeProtectionEnabled },
                        @{ Label = "IoAV Protection Enabled"; Value = $status.IoavProtectionEnabled },
                        @{ Label = "Antispyware Enabled"; Value = $status.AntispywareEnabled },
                        @{ Label = "Antivirus Enabled"; Value = $status.AntivirusEnabled },
                        @{ Label = "Behavior Monitor Enabled"; Value = $status.BehaviorMonitorEnabled },
                        @{ Label = "Network Inspection Enabled"; Value = $status.NISEnabled }
                    )
                    $protectionItems | ForEach-Object {
                        "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                    }
                } catch {
                    "Unable to retrieve protection status (requires elevation)"
                }

                Write-Output "`n3. Signature Information"
                Write-Output "-" * 50
                try {
                    $signatures = @(
                        @{ Label = "Signature Last Updated"; Value = $status.AntivirusSignatureLastUpdated },
                        @{ Label = "Signature Age (Days)"; Value = $status.AntivirusSignatureAge },
                        @{ Label = "Signature Version"; Value = $status.AntivirusSignatureVersion }
                    )
                    $signatures | ForEach-Object {
                        "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                    }
                } catch {
                    "Unable to retrieve signature information"
                }

                Write-Output "`n4. Scan Information"
                Write-Output "-" * 50
                try {
                    $scanInfo = @(
                        @{ Label = "Quick Scan Age (Days)"; Value = $status.QuickScanAge },
                        @{ Label = "Full Scan Age (Days)"; Value = $status.FullScanAge },
                        @{ Label = "Last Quick Scan Time"; Value = $status.QuickScanEndTime },
                        @{ Label = "Last Full Scan Time"; Value = $status.FullScanEndTime }
                    )
                    $scanInfo | ForEach-Object {
                        "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                    }
                } catch {
                    "Unable to retrieve scan information"
                }
                """
                output = run_powershell_command(command)
                if not output:
                    output = "No Windows Defender information available"

                # Format as HTML
                html_output = f"""
                <div class="defender-settings-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Windows Defender Settings</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(output)}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "Windows Defender Settings:\n"
            table += "-" * 70 + "\n"
            command = """
            Write-Output "1. Service Status"
            Write-Output "-" * 50
            $defender = Get-Service -Name WinDefend
            "Service Name : Windows Defender"
            "Status      : $($defender.Status)"
            "Start Type  : $($defender.StartType)"

            Write-Output "`n2. Protection Status"
            Write-Output "-" * 50
            try {
                $status = Get-MpComputerStatus
                $protectionItems = @(
                    @{ Label = "Real-Time Protection Enabled"; Value = $status.RealTimeProtectionEnabled },
                    @{ Label = "IoAV Protection Enabled"; Value = $status.IoavProtectionEnabled },
                    @{ Label = "Antispyware Enabled"; Value = $status.AntispywareEnabled },
                    @{ Label = "Antivirus Enabled"; Value = $status.AntivirusEnabled },
                    @{ Label = "Behavior Monitor Enabled"; Value = $status.BehaviorMonitorEnabled },
                    @{ Label = "Network Inspection Enabled"; Value = $status.NISEnabled }
                )
                $protectionItems | ForEach-Object {
                    "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                }
            } catch {
                "Unable to retrieve protection status (requires elevation)"
            }

            Write-Output "`n3. Signature Information"
            Write-Output "-" * 50
            try {
                $signatures = @(
                    @{ Label = "Signature Last Updated"; Value = $status.AntivirusSignatureLastUpdated },
                    @{ Label = "Signature Age (Days)"; Value = $status.AntivirusSignatureAge },
                    @{ Label = "Signature Version"; Value = $status.AntivirusSignatureVersion }
                )
                $signatures | ForEach-Object {
                    "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                }
            } catch {
                "Unable to retrieve signature information"
            }

            Write-Output "`n4. Scan Information"
            Write-Output "-" * 50
            try {
                $scanInfo = @(
                    @{ Label = "Quick Scan Age (Days)"; Value = $status.QuickScanAge },
                    @{ Label = "Full Scan Age (Days)"; Value = $status.FullScanAge },
                    @{ Label = "Last Quick Scan Time"; Value = $status.QuickScanEndTime },
                    @{ Label = "Last Full Scan Time"; Value = $status.FullScanEndTime }
                )
                $scanInfo | ForEach-Object {
                    "{0,-30} : {1}" -f $_.Label, $(if ($null -eq $_.Value) { "N/A" } else { $_.Value })
                }
            } catch {
                "Unable to retrieve scan information"
            }
            """
            output = run_powershell_command(command)
            if not output:
                output = "No Windows Defender information available"
            return (table + output).encode()

    def get_certificates(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Define certificate stores to check
            $certStores = @(
                @{ Path = 'Cert:\\LocalMachine\\My'; Name = 'Local Machine - Personal' },
                @{ Path = 'Cert:\\LocalMachine\\Root'; Name = 'Local Machine - Trusted Root' },
                @{ Path = 'Cert:\\LocalMachine\\CA'; Name = 'Local Machine - Intermediate CA' },
                @{ Path = 'Cert:\\CurrentUser\\My'; Name = 'Current User - Personal' },
                @{ Path = 'Cert:\\CurrentUser\\Root'; Name = 'Current User - Trusted Root' },
                @{ Path = 'Cert:\\CurrentUser\\CA'; Name = 'Current User - Intermediate CA' }
            )

            # Create a hashtable to store certificates by store
            $certsByStore = @{}

            # Process each certificate store
            foreach ($store in $certStores) {
                $certs = @()

                try {
                    $items = Get-ChildItem -Path $store.Path -ErrorAction Stop

                    if ($items) {
                        foreach ($cert in $items) {
                            $certs += @{
                                Subject = $cert.Subject
                                Issuer = $cert.Issuer
                                Thumbprint = $cert.Thumbprint
                                NotBefore = $cert.NotBefore
                                NotAfter = $cert.NotAfter
                                HasPrivateKey = $cert.HasPrivateKey
                                SerialNumber = $cert.SerialNumber
                                FriendlyName = if ($cert.FriendlyName) { $cert.FriendlyName } else { "N/A" }
                            }
                        }
                    }

                    $certsByStore[$store.Name] = @{
                        Path = $store.Path
                        Certificates = $certs
                    }
                } catch {
                    $certsByStore[$store.Name] = @{
                        Path = $store.Path
                        Error = "Could not access certificate store: $($_.Exception.Message)"
                        Certificates = @()
                    }
                }
            }

            # Create HTML output with cards for each store
            $htmlOutput = @"
            <div class="certificates-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="cert-search" placeholder="Search certificates..." onkeyup="filterCertificates()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearCertSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by subject, issuer, or thumbprint</div>
                </div>

                <script>
                function filterCertificates() {
                    const searchText = document.getElementById('cert-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.cert-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const subject = row.querySelector('.cert-subject').textContent.toLowerCase();
                        const issuer = row.querySelector('.cert-issuer').textContent.toLowerCase();
                        const thumbprint = row.querySelector('.cert-thumbprint').textContent.toLowerCase();

                        if (searchText === '' || subject.includes(searchText) || issuer.includes(searchText) || thumbprint.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.cert-store').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.cert-store').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });
                }

                function clearCertSearch() {
                    document.getElementById('cert-search').value = '';
                    filterCertificates();
                }
                </script>

                <div class="row">
"@

            # Process each certificate store
            foreach ($storeName in $certsByStore.Keys) {
                $storeInfo = $certsByStore[$storeName]
                $certs = $storeInfo.Certificates
                $storePath = $storeInfo.Path
                $storeError = $storeInfo.Error

                $storeId = $storeName.Replace(" ", "-").Replace(".", "").ToLower()

                # Choose card color based on store type
                $cardColor = switch -Wildcard ($storeName) {
                    "*Root*" { "bg-danger" }
                    "*CA*" { "bg-warning" }
                    "*Personal*" { "bg-success" }
                    default { "bg-primary" }
                }

                $htmlOutput += @"
                    <div class="col-md-12 mb-4 cert-store" id="store-$storeId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">$storeName</h5>
                                    <span class="badge bg-light text-dark">$($certs.Count) certificates</span>
                                </div>
                                <small>$([System.Web.HttpUtility]::HtmlEncode($storePath))</small>
                            </div>
                            <div class="card-body p-0">
"@

                if ($storeError) {
                    $htmlOutput += @"
                                <div class="alert alert-danger m-3">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    $([System.Web.HttpUtility]::HtmlEncode($storeError))
                                </div>
"@
                } elseif ($certs.Count -eq 0) {
                    $htmlOutput += @"
                                <div class="alert alert-info m-3">
                                    <i class="fas fa-info-circle me-2"></i>
                                    No certificates found in this store.
                                </div>
"@
                } else {
                    $htmlOutput += @"
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Subject</th>
                                                <th>Issuer</th>
                                                <th>Valid Until</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                    foreach ($cert in $certs) {
                        $subject = [System.Web.HttpUtility]::HtmlEncode($cert.Subject)
                        $issuer = [System.Web.HttpUtility]::HtmlEncode($cert.Issuer)
                        $thumbprint = [System.Web.HttpUtility]::HtmlEncode($cert.Thumbprint)
                        $validUntil = $cert.NotAfter.ToString("yyyy-MM-dd")
                        $validFrom = $cert.NotBefore.ToString("yyyy-MM-dd")

                        # Determine certificate status
                        $now = Get-Date
                        $status = ""
                        $statusClass = ""

                        if ($now -lt $cert.NotBefore) {
                            $status = "Not Yet Valid"
                            $statusClass = "text-warning"
                        } elseif ($now -gt $cert.NotAfter) {
                            $status = "Expired"
                            $statusClass = "text-danger"
                        } else {
                            $daysRemaining = ($cert.NotAfter - $now).Days

                            if ($daysRemaining -lt 30) {
                                $status = "Expiring Soon ($daysRemaining days)"
                                $statusClass = "text-warning"
                            } else {
                                $status = "Valid"
                                $statusClass = "text-success"
                            }
                        }

                        # Format subject for display (extract CN if possible)
                        $displaySubject = $subject
                        if ($subject -match "CN=([^,]+)") {
                            $displaySubject = $matches[1]
                        }

                        # Format issuer for display (extract CN if possible)
                        $displayIssuer = $issuer
                        if ($issuer -match "CN=([^,]+)") {
                            $displayIssuer = $matches[1]
                        }

                        $htmlOutput += @"
                                            <tr class="cert-row">
                                                <td class="cert-subject" title="$subject">$displaySubject</td>
                                                <td class="cert-issuer" title="$issuer">$displayIssuer</td>
                                                <td title="Valid from: $validFrom">$validUntil</td>
                                                <td class="$statusClass cert-thumbprint" title="Thumbprint: $thumbprint">$status</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
"@
                }

                $htmlOutput += @"
                            </div>
                        </div>
                    </div>
"@
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "System Certificates:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($storeName in $certsByStore.Keys) {
                $storeInfo = $certsByStore[$storeName]
                $certs = $storeInfo.Certificates
                $storePath = $storeInfo.Path
                $storeError = $storeInfo.Error

                $textOutput += "`n$storeName ($storePath):`n"
                $textOutput += "-" * 50 + "`n"

                if ($storeError) {
                    $textOutput += "Error: $storeError`n"
                } elseif ($certs.Count -eq 0) {
                    $textOutput += "No certificates found in this store.`n"
                } else {
                    foreach ($cert in $certs) {
                        # Format subject for display (extract CN if possible)
                        $displaySubject = $cert.Subject
                        if ($cert.Subject -match "CN=([^,]+)") {
                            $displaySubject = $matches[1]
                        }

                        # Determine certificate status
                        $now = Get-Date
                        $status = ""

                        if ($now -lt $cert.NotBefore) {
                            $status = "Not Yet Valid"
                        } elseif ($now -gt $cert.NotAfter) {
                            $status = "Expired"
                        } else {
                            $daysRemaining = ($cert.NotAfter - $now).Days

                            if ($daysRemaining -lt 30) {
                                $status = "Expiring Soon ($daysRemaining days)"
                            } else {
                                $status = "Valid"
                            }
                        }

                        $textOutput += "Subject     : $displaySubject`n"
                        $textOutput += "Issuer      : $($cert.Issuer)`n"
                        $textOutput += "Valid From  : $($cert.NotBefore.ToString('yyyy-MM-dd'))`n"
                        $textOutput += "Valid Until : $($cert.NotAfter.ToString('yyyy-MM-dd'))`n"
                        $textOutput += "Status      : $status`n"
                        $textOutput += "Thumbprint  : $($cert.Thumbprint)`n"
                        $textOutput += "Private Key : $($cert.HasPrivateKey)`n"
                        $textOutput += "-" * 50 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "System Certificates:\n"
                table += "-" * 50 + "\n"
                command = "Get-ChildItem -Path 'Cert:\\LocalMachine\\My' | Format-Table -AutoSize"
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="certificates-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">System Certificates</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(output or "No certificates found")}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "System Certificates:\n"
            table += "-" * 50 + "\n"
            command = "Get-ChildItem -Path 'Cert:\\LocalMachine\\My' | Format-Table -AutoSize"
            return (table + run_powershell_command(command)).encode()

    def get_environment_variables(self):
        # Use PowerShell to get environment variables with better formatting
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get environment variables
            $envVars = Get-ChildItem Env: | Sort-Object Name

            # Group environment variables by category
            $categories = @{
                "System" = @("OS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "NUMBER_OF_PROCESSORS",
                            "COMPUTERNAME", "USERNAME", "USERDOMAIN", "LOGONSERVER", "SESSIONNAME", "HOMEPATH",
                            "HOMEDRIVE", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP");
                "Path" = @("PATH");
                "User" = @("USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEPATH", "HOMEDRIVE");
                "Programming" = @("JAVA_HOME", "PYTHON", "PYTHONPATH", "PYTHONHOME", "GOROOT", "GOPATH", "NODE_PATH");
                "Network" = @("USERDNSDOMAIN", "USERDOMAIN", "COMPUTERNAME")
            }

            # Create a lookup for categorizing variables
            $categoryLookup = @{}
            foreach ($category in $categories.Keys) {
                foreach ($varName in $categories[$category]) {
                    $categoryLookup[$varName] = $category
                }
            }

            # Categorize all environment variables
            $categorizedVars = @{}
            foreach ($env in $envVars) {
                $category = "Other"

                # Check if this variable belongs to a specific category
                if ($categoryLookup.ContainsKey($env.Name)) {
                    $category = $categoryLookup[$env.Name]
                }
                # Check if it starts with any category prefix
                elseif ($env.Name -like "JAVA_*") { $category = "Programming" }
                elseif ($env.Name -like "PYTHON*") { $category = "Programming" }
                elseif ($env.Name -like "NODE_*") { $category = "Programming" }
                elseif ($env.Name -like "GO*") { $category = "Programming" }
                elseif ($env.Name -like "VS*") { $category = "Programming" }

                # Initialize category if needed
                if (-not $categorizedVars.ContainsKey($category)) {
                    $categorizedVars[$category] = @()
                }

                # Add to the appropriate category
                $categorizedVars[$category] += @{
                    "Name" = $env.Name
                    "Value" = $env.Value
                }
            }

            # Create HTML output with search functionality and cards for each category
            $htmlOutput = @"
            <div class="env-vars-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="env-var-search" placeholder="Search environment variables..." onkeyup="filterEnvVars()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearEnvVarSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by variable name or value</div>
                </div>

                <script>
                function filterEnvVars() {
                    const searchText = document.getElementById('env-var-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.env-var-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const varName = row.querySelector('.env-var-name').textContent.toLowerCase();
                        const varValue = row.querySelector('.env-var-value').textContent.toLowerCase();

                        if (searchText === '' || varName.includes(searchText) || varValue.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.env-var-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.env-var-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });
                }

                function clearEnvVarSearch() {
                    document.getElementById('env-var-search').value = '';
                    filterEnvVars();
                }
                </script>

                <div class="row">
"@

            # Sort categories to ensure consistent order
            $sortedCategories = $categorizedVars.Keys | Sort-Object

            # Process each category
            foreach ($category in $sortedCategories) {
                $categoryId = $category.Replace(" ", "-").ToLower()
                $htmlOutput += @"
                    <div class="col-md-12 mb-4 env-var-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">$category</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th style="width: 30%">Variable</th>
                                                <th>Value</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                # Sort variables within each category
                $sortedVars = $categorizedVars[$category] | Sort-Object -Property Name

                foreach ($var in $sortedVars) {
                    $varName = [System.Web.HttpUtility]::HtmlEncode($var.Name)
                    $varValue = [System.Web.HttpUtility]::HtmlEncode($var.Value)

                    $htmlOutput += @"
                                            <tr class="env-var-row">
                                                <td style="font-weight: 500; font-family: 'Consolas', monospace;" class="env-var-name">$varName</td>
                                                <td style="word-break: break-word; font-family: 'Consolas', monospace;" class="env-var-value">$varValue</td>
                                            </tr>
"@
                }

                $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
"@
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Environment Variables:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $sortedCategories) {
                $textOutput += "`n$category:`n"
                $textOutput += "-" * 30 + "`n"

                $sortedVars = $categorizedVars[$category] | Sort-Object -Property Name

                foreach ($var in $sortedVars) {
                    $textOutput += "{0,-30} {1}`n" -f $var.Name, $var.Value
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 3 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except:
                # Fallback to original method if PowerShell approach fails
                env_vars = []
                for key, value in os.environ.items():
                    # Ensure proper handling of backslashes and special characters
                    safe_value = value.replace('\\', '\\\\')
                    env_vars.append({'key': key, 'value': safe_value})

                # Format the output
                output = self.format_output("Environment Variables", env_vars, is_table=False)
                return output['html'].encode()
        else:
            # For terminal display, use the original method
            env_vars = []
            for key, value in os.environ.items():
                # Ensure proper handling of backslashes and special characters
                safe_value = value.replace('\\', '\\\\')
                env_vars.append({'key': key, 'value': safe_value})

            # Format the output
            output = self.format_output("Environment Variables", env_vars, is_table=False)
            return output['text'].encode()

    def list_user_folders(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Define the folders to list
            $userFolders = @("Downloads", "Documents", "Desktop", "Pictures", "Videos", "Music")

            # Create a hashtable to store folder contents
            $folderContents = @{}

            # Get contents of each folder
            foreach ($folder in $userFolders) {
                $path = [System.Environment]::GetFolderPath($folder)
                if (-not $path) {
                    # If GetFolderPath doesn't work, try the user profile path
                    $path = Join-Path $env:USERPROFILE $folder
                }

                if (Test-Path $path) {
                    try {
                        $items = Get-ChildItem -Path $path -ErrorAction Stop |
                                 Select-Object Name,
                                              @{Name="Type"; Expression={if($_.PSIsContainer){"Folder"}else{$_.Extension}}},
                                              Length,
                                              LastWriteTime
                        $folderContents[$folder] = @{
                            Path = $path
                            Items = $items
                            Error = $null
                        }
                    } catch {
                        $folderContents[$folder] = @{
                            Path = $path
                            Items = @()
                            Error = $_.Exception.Message
                        }
                    }
                } else {
                    $folderContents[$folder] = @{
                        Path = $path
                        Items = @()
                        Error = "Folder not found"
                    }
                }
            }

            # Create HTML output with cards for each folder
            $htmlOutput = @"
            <div class="user-folders-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="folder-item-search" placeholder="Search files and folders..." onkeyup="filterFolderItems()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearFolderSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by file name or type</div>
                </div>

                <script>
                function filterFolderItems() {
                    const searchText = document.getElementById('folder-item-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.folder-item-row');

                    let visibleFolders = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const itemName = row.querySelector('.item-name').textContent.toLowerCase();
                        const itemType = row.querySelector('.item-type').textContent.toLowerCase();

                        if (searchText === '' || itemName.includes(searchText) || itemType.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's folder to the visible set
                            const folderId = row.closest('.folder-card').id;
                            visibleFolders.add(folderId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide folder cards based on whether they have visible rows
                    document.querySelectorAll('.folder-card').forEach(folder => {
                        if (visibleFolders.has(folder.id) || searchText === '') {
                            folder.style.display = '';
                        } else {
                            folder.style.display = 'none';
                        }
                    });
                }

                function clearFolderSearch() {
                    document.getElementById('folder-item-search').value = '';
                    filterFolderItems();
                }
                </script>

                <div class="row">
"@

            # Process each folder
            foreach ($folder in $userFolders) {
                $folderInfo = $folderContents[$folder]
                $folderPath = $folderInfo.Path
                $items = $folderInfo.Items
                $error = $folderInfo.Error

                $folderId = $folder.ToLower()
                $htmlOutput += @"
                    <div class="col-md-6 mb-4 folder-card" id="folder-$folderId">
                        <div class="card h-100">
                            <div class="card-header bg-primary text-white">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">$folder</h5>
                                    <small>$([System.Web.HttpUtility]::HtmlEncode($folderPath))</small>
                                </div>
                            </div>
                            <div class="card-body p-0">
"@

                if ($error) {
                    $htmlOutput += @"
                                <div class="alert alert-warning m-3">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    $([System.Web.HttpUtility]::HtmlEncode($error))
                                </div>
"@
                } elseif ($items.Count -eq 0) {
                    $htmlOutput += @"
                                <div class="alert alert-info m-3">
                                    <i class="fas fa-info-circle me-2"></i>
                                    This folder is empty.
                                </div>
"@
                } else {
                    $htmlOutput += @"
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Name</th>
                                                <th>Type</th>
                                                <th>Size</th>
                                                <th>Modified</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                    foreach ($item in $items) {
                        $itemName = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                        $itemType = if ($item.Type -eq "Folder") { "Folder" } else { [System.Web.HttpUtility]::HtmlEncode($item.Type) }

                        # Format size
                        $sizeDisplay = if ($item.Type -eq "Folder") {
                            "—"
                        } elseif ($item.Length -lt 1KB) {
                            "$($item.Length) B"
                        } elseif ($item.Length -lt 1MB) {
                            "{0:N1} KB" -f ($item.Length / 1KB)
                        } elseif ($item.Length -lt 1GB) {
                            "{0:N1} MB" -f ($item.Length / 1MB)
                        } else {
                            "{0:N2} GB" -f ($item.Length / 1GB)
                        }

                        # Format date
                        $dateDisplay = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")

                        # Choose icon based on type
                        $icon = if ($item.Type -eq "Folder") {
                            '<i class="fas fa-folder text-warning"></i>'
                        } elseif ($item.Type -match '\.(exe|msi|bat|cmd)$') {
                            '<i class="fas fa-cog text-primary"></i>'
                        } elseif ($item.Type -match '\.(jpg|jpeg|png|gif|bmp|tiff)$') {
                            '<i class="fas fa-image text-success"></i>'
                        } elseif ($item.Type -match '\.(mp3|wav|ogg|flac|m4a)$') {
                            '<i class="fas fa-music text-info"></i>'
                        } elseif ($item.Type -match '\.(mp4|avi|mkv|mov|wmv)$') {
                            '<i class="fas fa-video text-danger"></i>'
                        } elseif ($item.Type -match '\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$') {
                            '<i class="fas fa-file-alt text-secondary"></i>'
                        } elseif ($item.Type -match '\.(zip|rar|7z|tar|gz)$') {
                            '<i class="fas fa-archive text-dark"></i>'
                        } else {
                            '<i class="fas fa-file text-muted"></i>'
                        }

                        $htmlOutput += @"
                                            <tr class="folder-item-row">
                                                <td class="item-name">$icon <span style="margin-left: 5px;">$itemName</span></td>
                                                <td class="item-type">$itemType</td>
                                                <td>$sizeDisplay</td>
                                                <td>$dateDisplay</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
"@
                }

                $htmlOutput += @"
                            </div>
                        </div>
                    </div>
"@
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "User Folders Content:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($folder in $userFolders) {
                $folderInfo = $folderContents[$folder]
                $folderPath = $folderInfo.Path
                $items = $folderInfo.Items
                $error = $folderInfo.Error

                $textOutput += "`n$folder ($folderPath):`n"
                $textOutput += "-" * 50 + "`n"

                if ($error) {
                    $textOutput += "Error: $error`n"
                } elseif ($items.Count -eq 0) {
                    $textOutput += "This folder is empty.`n"
                } else {
                    foreach ($item in $items) {
                        $sizeDisplay = if ($item.Type -eq "Folder") {
                            "<DIR>"
                        } elseif ($item.Length -lt 1KB) {
                            "$($item.Length) B"
                        } elseif ($item.Length -lt 1MB) {
                            "{0:N1} KB" -f ($item.Length / 1KB)
                        } elseif ($item.Length -lt 1GB) {
                            "{0:N1} MB" -f ($item.Length / 1MB)
                        } else {
                            "{0:N2} GB" -f ($item.Length / 1GB)
                        }

                        $dateDisplay = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                        $textOutput += "{0,-40} {1,-10} {2,-15} {3}`n" -f $item.Name, $item.Type, $sizeDisplay, $dateDisplay
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "User Folders Content:\n"
                table += "-" * 50 + "\n"
                user_folders = ["Downloads", "Documents", "Desktop"]
                for folder in user_folders:
                    path = os.path.expanduser(f"~\\{folder}")
                    table += f"\n{folder}:\n"
                    table += "-" * 25 + "\n"
                    try:
                        for item in os.listdir(path):
                            table += f"- {item}\n"
                    except:
                        table += "Access denied or folder not found\n"

                # Format as HTML
                html_output = f"""
                <div class="user-folders-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">User Folders</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(table)}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "User Folders Content:\n"
            table += "-" * 50 + "\n"
            user_folders = ["Downloads", "Documents", "Desktop"]
            for folder in user_folders:
                path = os.path.expanduser(f"~\\{folder}")
                table += f"\n{folder}:\n"
                table += "-" * 25 + "\n"
                try:
                    for item in os.listdir(path):
                        table += f"- {item}\n"
                except:
                    table += "Access denied or folder not found\n"
            return table.encode()

    def get_file_version(self, file_path=r"C:\Windows\System32\notepad.exe"):
        table = "File Version Information:\n"
        table += "-" * 50 + "\n"
        command = f"""
        $fileInfo = (Get-Command '{file_path}').FileVersionInfo

        # Create a custom object with the properties we want to display
        $customInfo = [PSCustomObject]@{{
            FileName = $fileInfo.FileName
            FileVersion = $fileInfo.FileVersion
            ProductVersion = $fileInfo.ProductVersion
            ProductName = $fileInfo.ProductName
            CompanyName = $fileInfo.CompanyName
            FileDescription = $fileInfo.FileDescription
            InternalName = $fileInfo.InternalName
            OriginalFilename = $fileInfo.OriginalFilename
            Language = $fileInfo.Language
        }}

        # Format as HTML table for web display
        $htmlTable = @"
<div class="file-version-info">
    <h3>File Version Information for $(Split-Path $fileInfo.FileName -Leaf)</h3>
    <table class="table table-striped">
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>File Name</td><td>$($fileInfo.FileName)</td></tr>
        <tr><td>File Version</td><td>$($fileInfo.FileVersion)</td></tr>
        <tr><td>Product Version</td><td>$($fileInfo.ProductVersion)</td></tr>
        <tr><td>Product Name</td><td>$($fileInfo.ProductName)</td></tr>
        <tr><td>Company Name</td><td>$($fileInfo.CompanyName)</td></tr>
        <tr><td>File Description</td><td>$($fileInfo.FileDescription)</td></tr>
        <tr><td>Internal Name</td><td>$($fileInfo.InternalName)</td></tr>
        <tr><td>Original Filename</td><td>$($fileInfo.OriginalFilename)</td></tr>
        <tr><td>Language</td><td>$($fileInfo.Language)</td></tr>
    </table>
</div>
"@

        # Return both formats
        $result = @{{
            Text = $customInfo | Format-Table -AutoSize | Out-String
            Html = $htmlTable
        }} | ConvertTo-Json

        Write-Output $result
        """

        result = run_powershell_command(command)

        try:
            # Try to parse the JSON result
            import json
            data = json.loads(result)

            # If this is a web request, return HTML
            if 'web_display' in self.__dict__ and self.web_display:
                return data['Html'].encode()
            else:
                # Otherwise return plain text
                return (table + data['Text']).encode()
        except:
            # Fallback to original command if JSON parsing fails
            fallback_command = f"(Get-Command '{file_path}').FileVersionInfo | Format-Table -AutoSize"
            fallback_result = run_powershell_command(fallback_command)
            return (table + fallback_result).encode()

    def get_installed_hotfixes(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get hotfixes using different methods
            $hotfixData = @{
                "Security Hotfixes" = @()
                "Update Hotfixes" = @()
                "Other Hotfixes" = @()
            }

            # Method 1: Get-HotFix (most reliable but limited info)
            try {
                $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending

                foreach ($hotfix in $hotfixes) {
                    # Categorize hotfixes based on description
                    $category = "Other Hotfixes"
                    if ($hotfix.Description -match "Security") {
                        $category = "Security Hotfixes"
                    } elseif ($hotfix.Description -match "Update") {
                        $category = "Update Hotfixes"
                    }

                    $hotfixData[$category] += @{
                        ID = $hotfix.HotFixID
                        Description = $hotfix.Description
                        InstalledOn = if ($hotfix.InstalledOn) { $hotfix.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                        InstalledBy = $hotfix.InstalledBy
                        Source = "Get-HotFix"
                    }
                }
            } catch {
                $hotfixData["Other Hotfixes"] += @{
                    ID = "Error"
                    Description = "Failed to retrieve hotfixes using Get-HotFix: $($_.Exception.Message)"
                    InstalledOn = "Unknown"
                    InstalledBy = "Unknown"
                    Source = "Error"
                }
            }

            # Method 2: Try to get more detailed hotfix info via WMI
            try {
                $wmiHotfixes = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop |
                               Sort-Object -Property InstalledOn -Descending

                foreach ($hotfix in $wmiHotfixes) {
                    # Check if this hotfix is already in our list
                    $exists = $false
                    foreach ($category in $hotfixData.Keys) {
                        $exists = $exists -or ($hotfixData[$category] | Where-Object { $_.ID -eq $hotfix.HotFixID })
                    }

                    if (-not $exists) {
                        # Categorize hotfixes based on description
                        $category = "Other Hotfixes"
                        if ($hotfix.Description -match "Security") {
                            $category = "Security Hotfixes"
                        } elseif ($hotfix.Description -match "Update") {
                            $category = "Update Hotfixes"
                        }

                        $hotfixData[$category] += @{
                            ID = $hotfix.HotFixID
                            Description = $hotfix.Description
                            InstalledOn = if ($hotfix.InstalledOn) {
                                try { [DateTime]::Parse($hotfix.InstalledOn).ToString("yyyy-MM-dd") }
                                catch { $hotfix.InstalledOn }
                            } else { "Unknown" }
                            InstalledBy = $hotfix.InstalledBy
                            Source = "WMI"
                        }
                    }
                }
            } catch {
                # Just continue if this method fails
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="hotfixes-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="hotfix-search" placeholder="Search hotfixes..." onkeyup="filterHotfixes()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearHotfixSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by ID, description, or date</div>
                </div>

                <script>
                function filterHotfixes() {
                    const searchText = document.getElementById('hotfix-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.hotfix-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const id = row.querySelector('.hotfix-id').textContent.toLowerCase();
                        const description = row.querySelector('.hotfix-description').textContent.toLowerCase();
                        const date = row.querySelector('.hotfix-date').textContent.toLowerCase();

                        if (searchText === '' || id.includes(searchText) || description.includes(searchText) || date.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.hotfix-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.hotfix-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible hotfixes
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.hotfix-row:not([style*="display: none"])').length;
                    const totalHotfixes = document.querySelectorAll('.hotfix-row').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalHotfixes;
                }

                function clearHotfixSearch() {
                    document.getElementById('hotfix-search').value = '';
                    filterHotfixes();
                }
                </script>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> installed hotfixes
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.hotfix-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.hotfix-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Process each category
            foreach ($category in @("Security Hotfixes", "Update Hotfixes", "Other Hotfixes")) {
                $hotfixes = $hotfixData[$category]

                if ($hotfixes.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $collapseId = "collapse-$categoryId"

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Security Hotfixes" { "bg-danger" }
                        "Update Hotfixes" { "bg-warning" }
                        "Other Hotfixes" { "bg-primary" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-md-12 mb-4 hotfix-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($hotfixes.Count) hotfixes</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
                            </div>
                            <div class="collapse show" id="$collapseId">
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th>HotFix ID</th>
                                                    <th>Description</th>
                                                    <th>Installed On</th>
                                                    <th>Installed By</th>
                                                </tr>
                                            </thead>
                                            <tbody>
"@

                    foreach ($hotfix in $hotfixes) {
                        $id = [System.Web.HttpUtility]::HtmlEncode($hotfix.ID)
                        $description = [System.Web.HttpUtility]::HtmlEncode($hotfix.Description)
                        $installedOn = [System.Web.HttpUtility]::HtmlEncode($hotfix.InstalledOn)
                        $installedBy = [System.Web.HttpUtility]::HtmlEncode($hotfix.InstalledBy)

                        $htmlOutput += @"
                                                <tr class="hotfix-row">
                                                    <td class="hotfix-id">$id</td>
                                                    <td class="hotfix-description">$description</td>
                                                    <td class="hotfix-date">$installedOn</td>
                                                    <td>$installedBy</td>
                                                </tr>
"@
                    }

                    $htmlOutput += @"
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalHotfixes = document.querySelectorAll('.hotfix-row').length;
                        document.getElementById('visible-count').textContent = totalHotfixes;
                        document.getElementById('total-count').textContent = totalHotfixes;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Installed Hotfixes:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in @("Security Hotfixes", "Update Hotfixes", "Other Hotfixes")) {
                $hotfixes = $hotfixData[$category]

                if ($hotfixes.Count -gt 0) {
                    $textOutput += "`n$category ($($hotfixes.Count) hotfixes):`n"
                    $textOutput += "-" * 50 + "`n"

                    foreach ($hotfix in $hotfixes) {
                        $textOutput += "ID          : $($hotfix.ID)`n"
                        $textOutput += "Description : $($hotfix.Description)`n"
                        $textOutput += "Installed On: $($hotfix.InstalledOn)`n"
                        $textOutput += "Installed By: $($hotfix.InstalledBy)`n"
                        $textOutput += "-" * 30 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                try:
                    # Try to get hotfixes via WMI
                    hotfixes = list(c.Win32_QuickFixEngineering())
                    if hotfixes:
                        # Format data for our output formatter
                        hotfix_data = []
                        for hotfix in hotfixes:
                            hotfix_data.append({
                                'HotFix ID': hotfix.HotFixID,
                                'Description': hotfix.Description
                            })

                        # Format the output
                        output = self.format_output("Installed Hotfixes", hotfix_data, headers=['HotFix ID', 'Description'])
                        return output['html'].encode()
                except:
                    # Fallback to simple PowerShell command
                    command = """
                    $hotfixes = Get-HotFix

                    # Create HTML table
                    $htmlTable = @"
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>HotFix ID</th>
                                    <th>Description</th>
                                    <th>Installed On</th>
                                </tr>
                            </thead>
                            <tbody>
                    "@

                    foreach ($hotfix in $hotfixes) {
                        $htmlTable += @"
                                <tr>
                                    <td>$($hotfix.HotFixID)</td>
                                    <td>$($hotfix.Description)</td>
                                    <td>$($hotfix.InstalledOn)</td>
                                </tr>
                    "@
                    }

                    $htmlTable += @"
                            </tbody>
                        </table>
                    </div>
                    "@
                    """
                    output = run_powershell_command(command)

                    # Format as HTML
                    html_output = f"""
                    <div class="hotfixes-container">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">Installed Hotfixes</h5>
                            </div>
                            <div class="card-body">
                                {output or '<div class="alert alert-info">No hotfixes found</div>'}
                            </div>
                        </div>
                    </div>
                    """

                    return html_output.encode()
        else:
            # For terminal display, use the original method
            try:
                # Try to get hotfixes via WMI
                hotfixes = list(c.Win32_QuickFixEngineering())
                if hotfixes:
                    # Format data for our output formatter
                    hotfix_data = []
                    for hotfix in hotfixes:
                        hotfix_data.append({
                            'HotFix ID': hotfix.HotFixID,
                            'Description': hotfix.Description
                        })

                    # Format the output
                    output = self.format_output("Installed Hotfixes", hotfix_data, headers=['HotFix ID', 'Description'])
                    return output['text'].encode()
                else:
                    # Fallback to PowerShell with text output
                    command = """
                    $hotfixes = Get-HotFix

                    # Create text table
                    $textTable = "Installed Hotfixes:`n"
                    $textTable += "-" * 70 + "`n"
                    $textTable += "HotFix ID      Description                  Installed On`n"
                    $textTable += "-" * 70 + "`n"

                    foreach ($hotfix in $hotfixes) {
                        $textTable += "{0,-15} {1,-30} {2}`n" -f $hotfix.HotFixID, $hotfix.Description, $hotfix.InstalledOn
                    }

                    Write-Output $textTable
                    """

                    result = run_powershell_command(command)

                    if not result:
                        # Fallback to simple format if PowerShell approach fails
                        fallback_command = "Get-HotFix | Format-Table -AutoSize"
                        fallback_result = run_powershell_command(fallback_command)

                        hotfixes_table = "Installed Hotfixes:\n"
                        hotfixes_table += "-" * 50 + "\n"
                        hotfixes_table += fallback_result if fallback_result else "No hotfixes found via PowerShell"
                        return hotfixes_table.encode()

                    return result.encode()
            except Exception as e:
                # Fallback to PowerShell with simple output
                ps_output = run_powershell_command("Get-HotFix | Format-Table -AutoSize")

                hotfixes_table = "Installed Hotfixes:\n"
                hotfixes_table += "-" * 50 + "\n"
                hotfixes_table += f"Error accessing WMI: {str(e)}\n\n"
                hotfixes_table += "Trying PowerShell method:\n"
                hotfixes_table += "-" * 50 + "\n"
                hotfixes_table += ps_output if ps_output else "No hotfixes found via PowerShell"

                return hotfixes_table.encode()

    def get_installed_products(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get installed software from both 32-bit and 64-bit registry locations
            $softwareLocations = @(
                @{ Path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Name = 'Standard Software' },
                @{ Path = 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Name = '32-bit Software' },
                @{ Path = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Name = 'User Software' }
            )

            # Create a hashtable to store software by category
            $softwareByCategory = @{}

            # Define common software categories
            $categoryPatterns = @{
                "Browsers" = @("chrome", "firefox", "edge", "opera", "safari", "browser")
                "Security" = @("antivirus", "firewall", "security", "defender", "protection", "mcafee", "norton", "kaspersky", "avast", "avg", "bitdefender")
                "Development" = @("visual studio", "vscode", "jetbrains", "intellij", "pycharm", "eclipse", "netbeans", "android studio", "git", "github", "node.js", "python", "java", "sdk", "development kit", "compiler")
                "Utilities" = @("7-zip", "winrar", "winzip", "ccleaner", "utility", "utilities", "tool", "tools")
                "Media" = @("vlc", "media player", "spotify", "itunes", "music", "video", "audio", "sound", "photo", "image", "camera")
                "Office" = @("microsoft office", "word", "excel", "powerpoint", "outlook", "onenote", "access", "libreoffice", "openoffice", "adobe acrobat", "pdf")
                "Gaming" = @("steam", "epic games", "origin", "uplay", "battle.net", "game", "gaming")
                "Communication" = @("skype", "teams", "zoom", "slack", "discord", "whatsapp", "telegram", "messenger")
            }

            # Process each software location
            foreach ($location in $softwareLocations) {
                if (Test-Path $location.Path) {
                    $apps = Get-ChildItem -Path $location.Path |
                            Get-ItemProperty |
                            Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize, @{Name="Source"; Expression={$location.Name}}

                    foreach ($app in $apps) {
                        # Determine category based on name and publisher
                        $appName = $app.DisplayName.ToLower()
                        $appPublisher = if ($app.Publisher) { $app.Publisher.ToLower() } else { "" }
                        $category = "Other"

                        foreach ($cat in $categoryPatterns.Keys) {
                            foreach ($pattern in $categoryPatterns[$cat]) {
                                if ($appName -match $pattern -or $appPublisher -match $pattern) {
                                    $category = $cat
                                    break
                                }
                            }
                            if ($category -ne "Other") { break }
                        }

                        # Special case for Microsoft products
                        if ($appPublisher -match "microsoft" -and $category -eq "Other") {
                            if ($appName -match "windows") {
                                $category = "Windows Components"
                            } else {
                                $category = "Microsoft"
                            }
                        }

                        # Initialize category if needed
                        if (-not $softwareByCategory.ContainsKey($category)) {
                            $softwareByCategory[$category] = @()
                        }

                        # Format install date
                        $installDate = if ($app.InstallDate) {
                            try {
                                # Try to parse as YYYYMMDD format
                                $dateStr = $app.InstallDate.ToString()
                                if ($dateStr.Length -eq 8) {
                                    $year = $dateStr.Substring(0, 4)
                                    $month = $dateStr.Substring(4, 2)
                                    $day = $dateStr.Substring(6, 2)
                                    "$year-$month-$day"
                                } else {
                                    $app.InstallDate
                                }
                            } catch {
                                $app.InstallDate
                            }
                        } else {
                            "Unknown"
                        }

                        # Format size
                        $sizeInMB = if ($app.EstimatedSize) {
                            [math]::Round($app.EstimatedSize / 1024, 2)
                        } else {
                            $null
                        }

                        # Add to the appropriate category
                        $softwareByCategory[$category] += @{
                            "Name" = $app.DisplayName
                            "Version" = if ($app.DisplayVersion) { $app.DisplayVersion } else { "N/A" }
                            "Publisher" = if ($app.Publisher) { $app.Publisher } else { "N/A" }
                            "InstallDate" = $installDate
                            "Size" = $sizeInMB
                            "Source" = $app.Source
                        }
                    }
                }
            }

            # Create HTML output with search functionality and cards for each category
            $htmlOutput = @"
            <div class="installed-software-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="software-search" placeholder="Search installed software..." onkeyup="filterSoftware()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearSoftwareSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by name, publisher, or version</div>
                </div>

                <script>
                function filterSoftware() {
                    const searchText = document.getElementById('software-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.software-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const name = row.querySelector('.software-name').textContent.toLowerCase();
                        const publisher = row.querySelector('.software-publisher').textContent.toLowerCase();
                        const version = row.querySelector('.software-version').textContent.toLowerCase();

                        if (searchText === '' || name.includes(searchText) || publisher.includes(searchText) || version.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.software-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.software-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible software
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.software-row:not([style*="display: none"])').length;
                    const totalSoftware = document.querySelectorAll('.software-row').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalSoftware;
                }

                function clearSoftwareSearch() {
                    document.getElementById('software-search').value = '';
                    filterSoftware();
                }
                </script>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> installed software items
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.software-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.software-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Sort categories to ensure consistent order
            $sortedCategories = $softwareByCategory.Keys | Sort-Object

            # Process each category
            $categoryIndex = 0
            foreach ($category in $sortedCategories) {
                $software = $softwareByCategory[$category]
                $categoryId = $category.Replace(" ", "-").ToLower()
                $collapseId = "collapse-$categoryId"

                # Choose card color based on category
                $cardColor = switch ($category) {
                    "Browsers" { "bg-info" }
                    "Security" { "bg-danger" }
                    "Development" { "bg-success" }
                    "Utilities" { "bg-warning" }
                    "Media" { "bg-primary" }
                    "Office" { "bg-secondary" }
                    "Gaming" { "bg-dark" }
                    "Communication" { "bg-info" }
                    "Windows Components" { "bg-primary" }
                    "Microsoft" { "bg-primary" }
                    default { "bg-primary" }
                }

                # Sort software by name
                $sortedSoftware = $software | Sort-Object -Property Name

                $htmlOutput += @"
                    <div class="col-md-12 mb-4 software-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($sortedSoftware.Count) items</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
                            </div>
                            <div class="collapse show" id="$collapseId">
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th style="width: 40%">Name</th>
                                                    <th style="width: 15%">Version</th>
                                                    <th style="width: 25%">Publisher</th>
                                                    <th style="width: 10%">Install Date</th>
                                                    <th style="width: 10%">Size (MB)</th>
                                                </tr>
                                            </thead>
                                            <tbody>
"@

                foreach ($app in $sortedSoftware) {
                    $name = [System.Web.HttpUtility]::HtmlEncode($app.Name)
                    $version = [System.Web.HttpUtility]::HtmlEncode($app.Version)
                    $publisher = [System.Web.HttpUtility]::HtmlEncode($app.Publisher)
                    $installDate = [System.Web.HttpUtility]::HtmlEncode($app.InstallDate)
                    $size = if ($app.Size) { $app.Size } else { "—" }

                    $htmlOutput += @"
                                                <tr class="software-row">
                                                    <td class="software-name">$name</td>
                                                    <td class="software-version">$version</td>
                                                    <td class="software-publisher">$publisher</td>
                                                    <td>$installDate</td>
                                                    <td>$size</td>
                                                </tr>
"@
                }

                $htmlOutput += @"
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"@

                $categoryIndex++
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalSoftware = document.querySelectorAll('.software-row').length;
                        document.getElementById('visible-count').textContent = totalSoftware;
                        document.getElementById('total-count').textContent = totalSoftware;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Installed Software:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $sortedCategories) {
                $software = $softwareByCategory[$category]
                $sortedSoftware = $software | Sort-Object -Property Name

                $textOutput += "`n$category ($($sortedSoftware.Count) items):`n"
                $textOutput += "-" * 50 + "`n"

                foreach ($app in $sortedSoftware) {
                    $name = if ($app.Name.Length -gt 30) { $app.Name.Substring(0, 27) + "..." } else { $app.Name }
                    $version = $app.Version
                    $publisher = $app.Publisher

                    $textOutput += "{0,-30} {1,-15} {2}`n" -f $name, $version, $publisher
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                command = """
                $products = Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' |
                           Get-ItemProperty |
                           Where-Object { $_.DisplayName } |
                           Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

                # Create HTML table
                $htmlTable = @"
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>Publisher</th>
                                <th>Install Date</th>
                            </tr>
                        </thead>
                        <tbody>
                "@

                foreach ($product in $products) {
                    $htmlTable += @"
                            <tr>
                                <td>$($product.DisplayName)</td>
                                <td>$($product.DisplayVersion)</td>
                                <td>$($product.Publisher)</td>
                                <td>$($product.InstallDate)</td>
                            </tr>
                "@
                }

                $htmlTable += @"
                        </tbody>
                    </table>
                </div>
                "@
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="installed-software-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Installed Software</h5>
                        </div>
                        <div class="card-body">
                            {output or '<div class="alert alert-info">No installed software found</div>'}
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            command = """
            $products = Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' |
                       Get-ItemProperty |
                       Where-Object { $_.DisplayName } |
                       Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

            # Create text table
            $textTable = "Installed Products:`n"
            $textTable += "-" * 70 + "`n"
            $textTable += "Name                           Version              Publisher`n"
            $textTable += "-" * 70 + "`n"

            foreach ($product in $products) {
                $name = if ($product.DisplayName.Length -gt 30) { $product.DisplayName.Substring(0, 27) + "..." } else { $product.DisplayName }
                $version = if ($product.DisplayVersion) { $product.DisplayVersion } else { "N/A" }
                $publisher = if ($product.Publisher) { $product.Publisher } else { "N/A" }

                $textTable += "{0,-30} {1,-20} {2}`n" -f $name, $version, $publisher
            }

            Write-Output $textTable
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            if not result:
                # Fallback to simple format if PowerShell approach fails
                fallback_command = "Get-ChildItem -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' | Get-ItemProperty | Select-Object DisplayName | Format-Table -AutoSize"
                fallback_result = run_powershell_command(fallback_command)

                products_table = "Installed Products:\n"
                products_table += "-" * 50 + "\n"
                products_table += fallback_result if fallback_result else "No products found"
                return products_table.encode()

            return result.encode()

    def get_non_empty_local_groups(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get local groups with detailed information
            $groupData = @{
                "Built-in Security Groups" = @()
                "Built-in System Groups" = @()
                "Custom Groups" = @()
            }

            # Define well-known built-in security groups
            $securityGroups = @(
                "Administrators", "Users", "Guests", "Power Users", "Remote Desktop Users",
                "Backup Operators", "Replicator", "Network Configuration Operators",
                "Performance Monitor Users", "Performance Log Users", "Distributed COM Users",
                "Cryptographic Operators", "Event Log Readers", "Certificate Service DCOM Access",
                "Remote Management Users"
            )

            # Define well-known system groups
            $systemGroups = @(
                "System Managed Accounts Group", "Storage Replica Administrators", "Access Control Assistance Operators",
                "Hyper-V Administrators", "Device Owners", "RDS Remote Access Servers", "RDS Endpoint Servers",
                "RDS Management Servers", "Windows Authorization Access Group"
            )

            try {
                # Get all local groups
                $groups = Get-LocalGroup -ErrorAction Stop | Where-Object { (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).count -gt 0 }

                # Process each group
                foreach ($group in $groups) {
                    # Get group members
                    $members = @()
                    try {
                        $groupMembers = Get-LocalGroupMember -Group $group.Name -ErrorAction Stop
                        if ($groupMembers) {
                            foreach ($member in $groupMembers) {
                                $members += @{
                                    Name = $member.Name
                                    ObjectClass = $member.ObjectClass
                                    PrincipalSource = $member.PrincipalSource
                                    SID = $member.SID.Value
                                }
                            }
                        }
                    } catch {
                        # Ignore errors when getting group members
                    }

                    # Determine group category
                    $category = "Custom Groups"
                    if ($securityGroups -contains $group.Name) {
                        $category = "Built-in Security Groups"
                    } elseif ($systemGroups -contains $group.Name) {
                        $category = "Built-in System Groups"
                    } elseif ($group.Name -like "NT SERVICE*" -or $group.Name -like "NT AUTHORITY*" -or
                              $group.Name -like "IIS_*" -or $group.Name -like "BUILTIN\\*") {
                        $category = "Built-in System Groups"
                    }

                    # Add to appropriate category
                    $groupData[$category] += @{
                        Name = $group.Name
                        Description = $group.Description
                        SID = $group.SID.Value
                        Members = $members
                        MemberCount = $members.Count
                    }
                }
            } catch {
                $groupData["Custom Groups"] += @{
                    Name = "Error"
                    Description = "Failed to retrieve groups: $($_.Exception.Message)"
                    SID = ""
                    Members = @()
                    MemberCount = 0
                }
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="local-groups-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="group-search" placeholder="Search groups..." onkeyup="filterGroups()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearGroupSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by group name, description, or member</div>
                </div>

                <script>
                function filterGroups() {
                    const searchText = document.getElementById('group-search').value.toLowerCase();
                    const cards = document.querySelectorAll('.group-card');

                    let visibleCategories = new Set();

                    // First pass: determine which cards should be visible
                    cards.forEach(card => {
                        const groupName = card.querySelector('.group-name').textContent.toLowerCase();
                        const groupDesc = card.querySelector('.group-description')?.textContent.toLowerCase() || '';
                        const members = card.querySelectorAll('.member-name');

                        let memberMatch = false;
                        members.forEach(member => {
                            if (member.textContent.toLowerCase().includes(searchText)) {
                                memberMatch = true;
                            }
                        });

                        if (searchText === '' || groupName.includes(searchText) || groupDesc.includes(searchText) || memberMatch) {
                            card.style.display = '';
                            // Add this card's category to the visible set
                            const categoryId = card.closest('.group-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            card.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible cards
                    document.querySelectorAll('.group-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible groups
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.group-card:not([style*="display: none"])').length;
                    const totalGroups = document.querySelectorAll('.group-card').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalGroups;
                }

                function clearGroupSearch() {
                    document.getElementById('group-search').value = '';
                    filterGroups();
                }

                function toggleGroupMembers(groupId) {
                    const membersList = document.getElementById('group-members-' + groupId);
                    if (membersList) {
                        membersList.classList.toggle('d-none');

                        const icon = document.getElementById('group-toggle-icon-' + groupId);
                        if (icon) {
                            if (membersList.classList.contains('d-none')) {
                                icon.classList.remove('fa-chevron-up');
                                icon.classList.add('fa-chevron-down');
                            } else {
                                icon.classList.remove('fa-chevron-down');
                                icon.classList.add('fa-chevron-up');
                            }
                        }
                    }
                }
                </script>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> local groups
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.group-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.group-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Process each category
            $categoryOrder = @("Built-in Security Groups", "Built-in System Groups", "Custom Groups")
            foreach ($category in $categoryOrder) {
                $groups = $groupData[$category]

                if ($groups.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $collapseId = "collapse-$categoryId"

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Built-in Security Groups" { "bg-danger" }
                        "Built-in System Groups" { "bg-warning" }
                        "Custom Groups" { "bg-success" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-md-12 mb-4 group-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($groups.Count) groups</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
                            </div>
                            <div class="collapse show" id="$collapseId">
                                <div class="card-body">
                                    <div class="row">
"@

                    $groupId = 0
                    foreach ($group in $groups) {
                        $groupId++
                        $groupName = [System.Web.HttpUtility]::HtmlEncode($group.Name)
                        $description = [System.Web.HttpUtility]::HtmlEncode($group.Description)
                        $memberCount = $group.MemberCount

                        $htmlOutput += @"
                        <div class="col-md-6 mb-3 group-card">
                            <div class="card h-100">
                                <div class="card-header bg-light">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <h6 class="mb-0 group-name">$groupName</h6>
                                        <span class="badge bg-secondary">$memberCount members</span>
                                    </div>
                                </div>
                                <div class="card-body">
                                    <p class="card-text group-description">$description</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <small class="text-muted">SID: $([System.Web.HttpUtility]::HtmlEncode($group.SID))</small>
                                        <button class="btn btn-sm btn-outline-primary" onclick="toggleGroupMembers('$groupId')">
                                            <i id="group-toggle-icon-$groupId" class="fas fa-chevron-down"></i>
                                            Members
                                        </button>
                                    </div>
                                    <div id="group-members-$groupId" class="mt-3 d-none">
"@

                        if ($memberCount -gt 0) {
                            $htmlOutput += @"
                                        <div class="list-group">
"@

                            foreach ($member in $group.Members) {
                                $memberName = [System.Web.HttpUtility]::HtmlEncode($member.Name)
                                $objectClass = [System.Web.HttpUtility]::HtmlEncode($member.ObjectClass)
                                $principalSource = [System.Web.HttpUtility]::HtmlEncode($member.PrincipalSource)

                                # Choose badge color based on object class
                                $badgeColor = switch ($objectClass) {
                                    "User" { "bg-success" }
                                    "Group" { "bg-info" }
                                    "Computer" { "bg-warning" }
                                    default { "bg-secondary" }
                                }

                                $htmlOutput += @"
                                            <div class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                                                <span class="member-name">$memberName</span>
                                                <span class="badge $badgeColor">$objectClass</span>
                                            </div>
"@
                            }

                            $htmlOutput += @"
                                        </div>
"@
                        } else {
                            $htmlOutput += @"
                                        <div class="alert alert-info">
                                            <i class="fas fa-info-circle me-2"></i>
                                            No members in this group
                                        </div>
"@
                        }

                        $htmlOutput += @"
                                    </div>
                                </div>
                            </div>
                        </div>
"@
                    }

                    $htmlOutput += @"
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalGroups = document.querySelectorAll('.group-card').length;
                        document.getElementById('visible-count').textContent = totalGroups;
                        document.getElementById('total-count').textContent = totalGroups;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Local Groups:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $categoryOrder) {
                $groups = $groupData[$category]

                if ($groups.Count -gt 0) {
                    $textOutput += "`n$category ($($groups.Count) groups):`n"
                    $textOutput += "-" * 50 + "`n"

                    foreach ($group in $groups) {
                        $textOutput += "Group Name    : $($group.Name)`n"
                        if ($group.Description) { $textOutput += "Description   : $($group.Description)`n" }
                        $textOutput += "Member Count  : $($group.MemberCount)`n"

                        if ($group.MemberCount -gt 0) {
                            $textOutput += "Members       : "
                            $memberNames = @()
                            foreach ($member in $group.Members) {
                                $memberNames += $member.Name
                            }
                            $textOutput += $memberNames -join ", "
                            $textOutput += "`n"
                        }

                        $textOutput += "-" * 30 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                # Use PowerShell to get local groups with HTML output
                command = """
                $groups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).count -gt 0 }

                # Create HTML table
                $htmlTable = @"
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>Group Name</th>
                                <th>Description</th>
                                <th>Members</th>
                            </tr>
                        </thead>
                        <tbody>
                "@

                foreach ($group in $groups) {
                    $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
                    $membersList = $members -join ", "

                    $htmlTable += @"
                            <tr>
                                <td>$($group.Name)</td>
                                <td>$($group.Description)</td>
                                <td>$membersList</td>
                            </tr>
                "@
                }

                $htmlTable += @"
                        </tbody>
                    </table>
                </div>
                "@
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="local-groups-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Local Groups</h5>
                        </div>
                        <div class="card-body">
                            {output or '<div class="alert alert-info">No groups with members found</div>'}
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            # Use PowerShell to get local groups with text output
            command = """
            $groups = Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).count -gt 0 }

            # Create text table
            $textTable = "Non-Empty Local Groups:`n"
            $textTable += "-" * 70 + "`n"
            $textTable += "Group Name                      Description`n"
            $textTable += "-" * 70 + "`n"

            foreach ($group in $groups) {
                $name = $group.Name
                $description = if ($group.Description) { $group.Description } else { "N/A" }

                $textTable += "{0,-30} {1}`n" -f $name, $description

                # Add members as indented lines
                $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
                if ($members) {
                    $textTable += "  Members:`n"
                    foreach ($member in $members) {
                        $textTable += "    - $member`n"
                    }
                }
                $textTable += "`n"
            }

            Write-Output $textTable
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            if not result:
                # Fallback to simple format if PowerShell approach fails
                fallback_command = "Get-LocalGroup | Where-Object { (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).count -gt 0 } | Format-Table -AutoSize"
                fallback_result = run_powershell_command(fallback_command)

                groups_table = "Non-Empty Local Groups:\n"
                groups_table += "-" * 50 + "\n"
                groups_table += fallback_result if fallback_result else "No non-empty groups found"
                return groups_table.encode()

            return result.encode()

    def get_local_users(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get local users with detailed information
            $userData = @{
                "Administrator Accounts" = @()
                "Standard User Accounts" = @()
                "System Accounts" = @()
                "Service Accounts" = @()
            }

            try {
                # Get all local users
                $users = Get-LocalUser -ErrorAction Stop

                # Get additional details for each user
                foreach ($user in $users) {
                    # Determine account type
                    $category = "Standard User Accounts"

                    # Check if user is in Administrators group
                    $isAdmin = $false
                    try {
                        $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
                        $adminMembers = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
                        $isAdmin = $adminMembers | Where-Object { $_.Name -like "*\\$($user.Name)" -or $_.SID -eq $user.SID }
                    } catch {
                        # Ignore errors when checking admin status
                    }

                    if ($isAdmin) {
                        $category = "Administrator Accounts"
                    } elseif ($user.Name -like "NT SERVICE*" -or $user.Name -like "NT AUTHORITY*") {
                        $category = "System Accounts"
                    } elseif ($user.Name -like "*$") {
                        $category = "Service Accounts"
                    }

                    # Get last logon time
                    $lastLogon = "Never"
                    try {
                        $userObj = New-Object System.Security.Principal.NTAccount($user.Name)
                        $sid = $userObj.Translate([System.Security.Principal.SecurityIdentifier])
                        $lastLogonTimestamp = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\$($sid.Value)" -Name "ProfileLoadTimeHigh", "ProfileLoadTimeLow" -ErrorAction SilentlyContinue

                        if ($lastLogonTimestamp) {
                            # Convert to datetime if available
                            try {
                                $high = $lastLogonTimestamp.ProfileLoadTimeHigh
                                $low = $lastLogonTimestamp.ProfileLoadTimeLow
                                if ($high -and $low) {
                                    $fileTime = $high -shl 32 -bor $low
                                    $lastLogon = [DateTime]::FromFileTime($fileTime).ToString("yyyy-MM-dd HH:mm:ss")
                                }
                            } catch {
                                # Keep as "Never" if conversion fails
                            }
                        }
                    } catch {
                        # Ignore errors when getting last logon time
                    }

                    # Get password information
                    $passwordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" }
                    $passwordExpires = if ($user.PasswordExpires) { $user.PasswordExpires.ToString("yyyy-MM-dd") } else { "Never" }

                    # Add to appropriate category
                    $userData[$category] += @{
                        Name = $user.Name
                        FullName = $user.FullName
                        Description = $user.Description
                        Enabled = $user.Enabled
                        LastLogon = $lastLogon
                        PasswordLastSet = $passwordLastSet
                        PasswordExpires = $passwordExpires
                        PasswordRequired = $user.PasswordRequired
                        UserMayChangePassword = $user.UserMayChangePassword
                        PasswordNeverExpires = $user.PasswordNeverExpires
                        AccountExpires = if ($user.AccountExpires) { $user.AccountExpires.ToString("yyyy-MM-dd") } else { "Never" }
                        SID = $user.SID.Value
                    }
                }
            } catch {
                $userData["Standard User Accounts"] += @{
                    Name = "Error"
                    FullName = ""
                    Description = "Failed to retrieve users: $($_.Exception.Message)"
                    Enabled = $false
                    LastLogon = "Unknown"
                    PasswordLastSet = "Unknown"
                    PasswordExpires = "Unknown"
                    PasswordRequired = $false
                    UserMayChangePassword = $false
                    PasswordNeverExpires = $false
                    AccountExpires = "Unknown"
                    SID = ""
                }
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="local-users-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="user-search" placeholder="Search users..." onkeyup="filterUsers()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearUserSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by username, description, or status</div>
                </div>

                <script>
                function filterUsers() {
                    const searchText = document.getElementById('user-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.user-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const username = row.querySelector('.user-name').textContent.toLowerCase();
                        const description = row.querySelector('.user-description')?.textContent.toLowerCase() || '';
                        const status = row.querySelector('.user-status').textContent.toLowerCase();

                        if (searchText === '' || username.includes(searchText) || description.includes(searchText) || status.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.user-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.user-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible users
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.user-row:not([style*="display: none"])').length;
                    const totalUsers = document.querySelectorAll('.user-row').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalUsers;
                }

                function clearUserSearch() {
                    document.getElementById('user-search').value = '';
                    filterUsers();
                }

                function toggleUserDetails(userId) {
                    const detailsRow = document.getElementById('user-details-' + userId);
                    if (detailsRow) {
                        detailsRow.classList.toggle('d-none');
                    }
                }
                </script>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> local users
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.user-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.user-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Process each category
            $categoryOrder = @("Administrator Accounts", "Standard User Accounts", "Service Accounts", "System Accounts")
            foreach ($category in $categoryOrder) {
                $users = $userData[$category]

                if ($users.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $collapseId = "collapse-$categoryId"

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Administrator Accounts" { "bg-danger" }
                        "Standard User Accounts" { "bg-success" }
                        "Service Accounts" { "bg-warning" }
                        "System Accounts" { "bg-secondary" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-md-12 mb-4 user-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($users.Count) users</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
                            </div>
                            <div class="collapse show" id="$collapseId">
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th>Username</th>
                                                    <th>Description</th>
                                                    <th>Status</th>
                                                    <th>Last Logon</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
"@

                    $userId = 0
                    foreach ($user in $users) {
                        $userId++
                        $username = [System.Web.HttpUtility]::HtmlEncode($user.Name)
                        $fullName = [System.Web.HttpUtility]::HtmlEncode($user.FullName)
                        $description = [System.Web.HttpUtility]::HtmlEncode($user.Description)
                        $status = if ($user.Enabled) { "Active" } else { "Disabled" }
                        $statusClass = if ($user.Enabled) { "text-success" } else { "text-danger" }
                        $lastLogon = [System.Web.HttpUtility]::HtmlEncode($user.LastLogon)

                        $htmlOutput += @"
                                                <tr class="user-row">
                                                    <td class="user-name">
                                                        <strong>$username</strong>
                                                        $(if ($fullName) { "<div><small>$fullName</small></div>" })
                                                    </td>
                                                    <td class="user-description">$description</td>
                                                    <td class="user-status $statusClass">$status</td>
                                                    <td>$lastLogon</td>
                                                    <td>
                                                        <button class="btn btn-sm btn-outline-primary" onclick="toggleUserDetails('$userId')">
                                                            <i class="fas fa-info-circle"></i> Details
                                                        </button>
                                                    </td>
                                                </tr>
                                                <tr id="user-details-$userId" class="d-none">
                                                    <td colspan="5">
                                                        <div class="card mb-0">
                                                            <div class="card-body">
                                                                <div class="row">
                                                                    <div class="col-md-6">
                                                                        <h6>Account Information</h6>
                                                                        <table class="table table-sm">
                                                                            <tr>
                                                                                <th>SID</th>
                                                                                <td><small>$([System.Web.HttpUtility]::HtmlEncode($user.SID))</small></td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>Account Expires</th>
                                                                                <td>$([System.Web.HttpUtility]::HtmlEncode($user.AccountExpires))</td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>Last Logon</th>
                                                                                <td>$lastLogon</td>
                                                                            </tr>
                                                                        </table>
                                                                    </div>
                                                                    <div class="col-md-6">
                                                                        <h6>Password Information</h6>
                                                                        <table class="table table-sm">
                                                                            <tr>
                                                                                <th>Password Last Set</th>
                                                                                <td>$([System.Web.HttpUtility]::HtmlEncode($user.PasswordLastSet))</td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>Password Expires</th>
                                                                                <td>$([System.Web.HttpUtility]::HtmlEncode($user.PasswordExpires))</td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>Password Required</th>
                                                                                <td>$(if ($user.PasswordRequired) { "Yes" } else { "No" })</td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>Password Never Expires</th>
                                                                                <td>$(if ($user.PasswordNeverExpires) { "Yes" } else { "No" })</td>
                                                                            </tr>
                                                                            <tr>
                                                                                <th>User May Change Password</th>
                                                                                <td>$(if ($user.UserMayChangePassword) { "Yes" } else { "No" })</td>
                                                                            </tr>
                                                                        </table>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                </tr>
"@
                    }

                    $htmlOutput += @"
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalUsers = document.querySelectorAll('.user-row').length;
                        document.getElementById('visible-count').textContent = totalUsers;
                        document.getElementById('total-count').textContent = totalUsers;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Local Users:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $categoryOrder) {
                $users = $userData[$category]

                if ($users.Count -gt 0) {
                    $textOutput += "`n$category ($($users.Count) users):`n"
                    $textOutput += "-" * 50 + "`n"

                    foreach ($user in $users) {
                        $status = if ($user.Enabled) { "Active" } else { "Disabled" }

                        $textOutput += "Username        : $($user.Name)`n"
                        if ($user.FullName) { $textOutput += "Full Name       : $($user.FullName)`n" }
                        if ($user.Description) { $textOutput += "Description     : $($user.Description)`n" }
                        $textOutput += "Status          : $status`n"
                        $textOutput += "Last Logon      : $($user.LastLogon)`n"
                        $textOutput += "Password Set    : $($user.PasswordLastSet)`n"
                        $textOutput += "Password Expires: $($user.PasswordExpires)`n"
                        $textOutput += "-" * 30 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                try:
                    # Try to get users via WMI
                    users = list(c.Win32_UserAccount())
                    if users:
                        # Format data for our output formatter
                        user_data = []
                        for user in users:
                            status = "Disabled" if user.Disabled else "Active"
                            user_data.append({
                                'Username': user.Name,
                                'Status': status
                            })

                        # Format the output
                        output = self.format_output("Local Users", user_data, headers=['Username', 'Status'])
                        return output['html'].encode()
                except:
                    # Fallback to simple PowerShell command
                    command = """
                    $users = Get-LocalUser

                    # Create HTML table
                    $htmlTable = @"
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>Username</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                    "@

                    foreach ($user in $users) {
                        $status = if ($user.Enabled) { "Active" } else { "Disabled" }
                        $htmlTable += @"
                                <tr>
                                    <td>$($user.Name)</td>
                                    <td>$status</td>
                                </tr>
                    "@
                    }

                    $htmlTable += @"
                            </tbody>
                        </table>
                    </div>
                    "@
                    """
                    output = run_powershell_command(command)

                    # Format as HTML
                    html_output = f"""
                    <div class="local-users-container">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">Local Users</h5>
                            </div>
                            <div class="card-body">
                                {output or '<div class="alert alert-info">No local users found</div>'}
                            </div>
                        </div>
                    </div>
                    """

                    return html_output.encode()
        else:
            # For terminal display, use the original method
            try:
                # Try to get users via WMI
                users = list(c.Win32_UserAccount())
                if users:
                    # Format data for our output formatter
                    user_data = []
                    for user in users:
                        status = "Disabled" if user.Disabled else "Active"
                        user_data.append({
                            'Username': user.Name,
                            'Status': status
                        })

                    # Format the output
                    output = self.format_output("Local Users", user_data, headers=['Username', 'Status'])
                    return output['text'].encode()
                else:
                    # Fallback to PowerShell with text output
                    command = """
                    $users = Get-LocalUser

                    # Create text table
                    $textTable = "Local Users:`n"
                    $textTable += "-" * 70 + "`n"
                    $textTable += "Username                        Status`n"
                    $textTable += "-" * 70 + "`n"

                    foreach ($user in $users) {
                        $status = if ($user.Enabled) { "Active" } else { "Disabled" }
                        $textTable += "{0,-30} {1}`n" -f $user.Name, $status
                    }

                    Write-Output $textTable
                    """

                    result = run_powershell_command(command)

                    if not result:
                        # Fallback to simple format if PowerShell approach fails
                        fallback_command = "Get-LocalUser | Format-Table Name,Enabled -AutoSize"
                        fallback_result = run_powershell_command(fallback_command)

                        users_table = "Local Users:\n"
                        users_table += "-" * 50 + "\n"
                        users_table += fallback_result if fallback_result else "No users found via PowerShell"
                        return users_table.encode()

                    return result.encode()
            except Exception as e:
                # Fallback to PowerShell with simple output
                ps_output = run_powershell_command("Get-LocalUser | Format-Table Name,Enabled -AutoSize")

                users_table = "Local Users:\n"
                users_table += "-" * 50 + "\n"
                users_table += f"Error accessing WMI: {str(e)}\n\n"
                users_table += "Trying PowerShell method:\n"
                users_table += "-" * 50 + "\n"
                users_table += ps_output if ps_output else "No users found via PowerShell"

                return users_table.encode()

    def get_ms_updates(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get Windows updates using different methods
            $updateData = @{
                "Security Updates" = @()
                "Critical Updates" = @()
                "Feature Updates" = @()
                "Other Updates" = @()
            }

            # Method 1: Get-HotFix (most reliable but limited info)
            try {
                $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending

                foreach ($update in $hotfixes) {
                    # Categorize updates based on description
                    $category = "Other Updates"
                    if ($update.Description -match "Security" -or $update.HotFixID -match "^KB[0-9]{7}$") {
                        $category = "Security Updates"
                    } elseif ($update.Description -match "Critical" -or $update.Description -match "Cumulative") {
                        $category = "Critical Updates"
                    } elseif ($update.Description -match "Feature") {
                        $category = "Feature Updates"
                    }

                    $updateData[$category] += @{
                        ID = $update.HotFixID
                        Description = $update.Description
                        InstalledOn = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                        InstalledBy = $update.InstalledBy
                        Source = "Get-HotFix"
                    }
                }
            } catch {
                $updateData["Other Updates"] += @{
                    ID = "Error"
                    Description = "Failed to retrieve updates using Get-HotFix: $($_.Exception.Message)"
                    InstalledOn = "Unknown"
                    InstalledBy = "Unknown"
                    Source = "Error"
                }
            }

            # Method 2: Try to get more detailed update info (Windows 10/11)
            try {
                # This might not work on all systems
                $windowsUpdates = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop |
                                  Sort-Object -Property InstalledOn -Descending

                foreach ($update in $windowsUpdates) {
                    # Check if this update is already in our list
                    $exists = $false
                    foreach ($category in $updateData.Keys) {
                        $exists = $exists -or ($updateData[$category] | Where-Object { $_.ID -eq $update.HotFixID })
                    }

                    if (-not $exists) {
                        # Categorize updates based on description
                        $category = "Other Updates"
                        if ($update.Description -match "Security") {
                            $category = "Security Updates"
                        } elseif ($update.Description -match "Critical" -or $update.Description -match "Cumulative") {
                            $category = "Critical Updates"
                        } elseif ($update.Description -match "Feature") {
                            $category = "Feature Updates"
                        }

                        $updateData[$category] += @{
                            ID = $update.HotFixID
                            Description = $update.Description
                            InstalledOn = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                            InstalledBy = $update.InstalledBy
                            Source = "WMI"
                        }
                    }
                }
            } catch {
                # Just continue if this method fails
            }

            # Create HTML output with cards for each category
            $htmlOutput = @"
            <div class="windows-updates-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="update-search" placeholder="Search Windows updates..." onkeyup="filterUpdates()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearUpdateSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by ID, description, or date</div>
                </div>

                <script>
                function filterUpdates() {
                    const searchText = document.getElementById('update-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.update-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const id = row.querySelector('.update-id').textContent.toLowerCase();
                        const description = row.querySelector('.update-description').textContent.toLowerCase();
                        const date = row.querySelector('.update-date').textContent.toLowerCase();

                        if (searchText === '' || id.includes(searchText) || description.includes(searchText) || date.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.update-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.update-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible updates
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.update-row:not([style*="display: none"])').length;
                    const totalUpdates = document.querySelectorAll('.update-row').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalUpdates;
                }

                function clearUpdateSearch() {
                    document.getElementById('update-search').value = '';
                    filterUpdates();
                }
                </script>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> Windows updates
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.update-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.update-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Process each category
            foreach ($category in @("Security Updates", "Critical Updates", "Feature Updates", "Other Updates")) {
                $updates = $updateData[$category]

                if ($updates.Count -gt 0) {
                    $categoryId = $category.Replace(" ", "-").ToLower()
                    $collapseId = "collapse-$categoryId"

                    # Choose card color based on category
                    $cardColor = switch ($category) {
                        "Security Updates" { "bg-danger" }
                        "Critical Updates" { "bg-warning" }
                        "Feature Updates" { "bg-success" }
                        "Other Updates" { "bg-primary" }
                        default { "bg-primary" }
                    }

                    $htmlOutput += @"
                    <div class="col-md-12 mb-4 update-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($updates.Count) updates</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
                            </div>
                            <div class="collapse show" id="$collapseId">
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th>Update ID</th>
                                                    <th>Description</th>
                                                    <th>Installed On</th>
                                                    <th>Installed By</th>
                                                </tr>
                                            </thead>
                                            <tbody>
"@

                    foreach ($update in $updates) {
                        $id = [System.Web.HttpUtility]::HtmlEncode($update.ID)
                        $description = [System.Web.HttpUtility]::HtmlEncode($update.Description)
                        $installedOn = [System.Web.HttpUtility]::HtmlEncode($update.InstalledOn)
                        $installedBy = [System.Web.HttpUtility]::HtmlEncode($update.InstalledBy)

                        $htmlOutput += @"
                                                <tr class="update-row">
                                                    <td class="update-id">$id</td>
                                                    <td class="update-description">$description</td>
                                                    <td class="update-date">$installedOn</td>
                                                    <td>$installedBy</td>
                                                </tr>
"@
                    }

                    $htmlOutput += @"
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalUpdates = document.querySelectorAll('.update-row').length;
                        document.getElementById('visible-count').textContent = totalUpdates;
                        document.getElementById('total-count').textContent = totalUpdates;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Windows Updates:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in @("Security Updates", "Critical Updates", "Feature Updates", "Other Updates")) {
                $updates = $updateData[$category]

                if ($updates.Count -gt 0) {
                    $textOutput += "`n$category ($($updates.Count) updates):`n"
                    $textOutput += "-" * 50 + "`n"

                    foreach ($update in $updates) {
                        $textOutput += "ID          : $($update.ID)`n"
                        $textOutput += "Description : $($update.Description)`n"
                        $textOutput += "Installed On: $($update.InstalledOn)`n"
                        $textOutput += "Installed By: $($update.InstalledBy)`n"
                        $textOutput += "-" * 30 + "`n"
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                command = """
                $updates = Get-HotFix

                # Create HTML table
                $htmlTable = @"
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>HotFix ID</th>
                                <th>Description</th>
                                <th>Installed On</th>
                                <th>Installed By</th>
                            </tr>
                        </thead>
                        <tbody>
                "@

                foreach ($update in $updates) {
                    $htmlTable += @"
                            <tr>
                                <td>$($update.HotFixID)</td>
                                <td>$($update.Description)</td>
                                <td>$($update.InstalledOn)</td>
                                <td>$($update.InstalledBy)</td>
                            </tr>
                "@
                }

                $htmlTable += @"
                        </tbody>
                    </table>
                </div>
                "@
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="windows-updates-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Windows Updates</h5>
                        </div>
                        <div class="card-body">
                            {output or '<div class="alert alert-info">No Windows updates found</div>'}
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            command = """
            $updates = Get-HotFix

            # Create text table
            $textTable = "Microsoft Updates:`n"
            $textTable += "-" * 70 + "`n"
            $textTable += "HotFix ID      Description                  Installed On         Installed By`n"
            $textTable += "-" * 70 + "`n"

            foreach ($update in $updates) {
                $textTable += "{0,-15} {1,-30} {2,-20} {3}`n" -f $update.HotFixID, $update.Description, $update.InstalledOn, $update.InstalledBy
            }

            Write-Output $textTable
            """

            result = run_powershell_command(command)

            if not result:
                # Fallback to simple format if PowerShell approach fails
                fallback_command = "Get-HotFix | Format-Table -AutoSize"
                fallback_result = run_powershell_command(fallback_command)

                updates_table = "Microsoft Updates:\n"
                updates_table += "-" * 50 + "\n"
                updates_table += fallback_result if fallback_result else "No updates found"
                return updates_table.encode()

            return result.encode()

    def get_ntlm_settings(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get NTLM settings from registry
            $ntlmSettings = @()

            try {
                # Get LSA settings
                $lsaPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
                $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction Stop

                # NoLMHash - prevents storage of LM hash
                $ntlmSettings += @{
                    Name = "NoLMHash"
                    Value = if ($lsa.NoLMHash -eq 1) { "Enabled (LM hash storage prevented)" } else { "Disabled (LM hash may be stored)" }
                    Description = "Controls whether the LM hash of the password is stored when passwords are changed"
                }

                # LmCompatibilityLevel - controls NTLM authentication level
                if ($null -ne $lsa.LmCompatibilityLevel) {
                    $levelDesc = switch ($lsa.LmCompatibilityLevel) {
                        0 { "Send LM & NTLM responses (least secure)" }
                        1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
                        2 { "Send NTLM response only" }
                        3 { "Send NTLMv2 response only" }
                        4 { "Send NTLMv2 response only, refuse LM" }
                        5 { "Send NTLMv2 response only, refuse LM & NTLM (most secure)" }
                        default { "Unknown setting" }
                    }
                    $ntlmSettings += @{
                        Name = "LmCompatibilityLevel"
                        Value = "$($lsa.LmCompatibilityLevel) - $levelDesc"
                        Description = "Controls the authentication protocols used by clients and accepted by servers"
                    }
                }

                # NTLMMinClientSec - minimum security for NTLM SSP clients
                if ($null -ne $lsa.NTLMMinClientSec) {
                    $ntlmSettings += @{
                        Name = "NTLMMinClientSec"
                        Value = "0x$($lsa.NTLMMinClientSec.ToString('X8'))"
                        Description = "Minimum security requirements for NTLM SSP-based clients"
                    }
                }

                # NTLMMinServerSec - minimum security for NTLM SSP servers
                if ($null -ne $lsa.NTLMMinServerSec) {
                    $ntlmSettings += @{
                        Name = "NTLMMinServerSec"
                        Value = "0x$($lsa.NTLMMinServerSec.ToString('X8'))"
                        Description = "Minimum security requirements for NTLM SSP-based servers"
                    }
                }

                # RestrictSendingNTLMTraffic - controls outbound NTLM traffic
                $ntlmSecPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0'
                if (Test-Path $ntlmSecPath) {
                    $ntlmSec = Get-ItemProperty -Path $ntlmSecPath -ErrorAction SilentlyContinue

                    if ($null -ne $ntlmSec.RestrictSendingNTLMTraffic) {
                        $restrictDesc = switch ($ntlmSec.RestrictSendingNTLMTraffic) {
                            0 { "Allow all (least secure)" }
                            1 { "Audit all" }
                            2 { "Deny all (most secure)" }
                            default { "Unknown setting" }
                        }
                        $ntlmSettings += @{
                            Name = "RestrictSendingNTLMTraffic"
                            Value = "$($ntlmSec.RestrictSendingNTLMTraffic) - $restrictDesc"
                            Description = "Controls outbound NTLM authentication traffic from this computer"
                        }
                    }

                    # Other NTLM security settings
                    $ntlmProps = $ntlmSec.PSObject.Properties | Where-Object {
                        $_.Name -match 'NTLM|ClientAllowedNTLMServers|DCAllowedNTLMServers' -and
                        $_.Name -notmatch '^PS'
                    }

                    foreach ($prop in $ntlmProps) {
                        $ntlmSettings += @{
                            Name = $prop.Name
                            Value = $prop.Value
                            Description = "NTLM security setting"
                        }
                    }
                }

                # Check for NTLM network security settings
                $netlogonPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters'
                if (Test-Path $netlogonPath) {
                    $netlogon = Get-ItemProperty -Path $netlogonPath -ErrorAction SilentlyContinue

                    # Check for relevant NTLM settings
                    $netlogonProps = $netlogon.PSObject.Properties | Where-Object {
                        $_.Name -match 'NTLM|RequireSign|RequireStrongKey|SealSecureChannel|SignSecureChannel' -and
                        $_.Name -notmatch '^PS'
                    }

                    foreach ($prop in $netlogonProps) {
                        $value = if ($prop.Value -eq 1) { "Enabled" } elseif ($prop.Value -eq 0) { "Disabled" } else { $prop.Value }
                        $ntlmSettings += @{
                            Name = $prop.Name
                            Value = $value
                            Description = "Netlogon secure channel setting"
                        }
                    }
                }

                # If no settings were found
                if ($ntlmSettings.Count -eq 0) {
                    $ntlmSettings += @{
                        Name = "Status"
                        Value = "No NTLM settings found"
                        Description = "Could not find any NTLM-related settings in the registry"
                    }
                }
            }
            catch {
                $ntlmSettings += @{
                    Name = "Error"
                    Value = $_.Exception.Message
                    Description = "Error accessing NTLM settings"
                }
            }

            # Create HTML output with card-based layout
            $htmlOutput = @"
            <div class="ntlm-settings-container">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">NTLM Security Settings</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th style="width: 25%">Setting</th>
                                        <th style="width: 35%">Value</th>
                                        <th style="width: 40%">Description</th>
                                    </tr>
                                </thead>
                                <tbody>
"@

            foreach ($setting in $ntlmSettings) {
                $name = [System.Web.HttpUtility]::HtmlEncode($setting.Name)
                $value = [System.Web.HttpUtility]::HtmlEncode($setting.Value)
                $description = [System.Web.HttpUtility]::HtmlEncode($setting.Description)

                $htmlOutput += @"
                                    <tr>
                                        <td><strong>$name</strong></td>
                                        <td>$value</td>
                                        <td><em>$description</em></td>
                                    </tr>
"@
            }

            $htmlOutput += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "NTLM Settings:`n"
            $textOutput += "-" * 70 + "`n"
            $textOutput += "Setting                         Value                                   Description`n"
            $textOutput += "-" * 100 + "`n"

            foreach ($setting in $ntlmSettings) {
                $textOutput += "{0,-30} {1,-40} {2}`n" -f $setting.Name, $setting.Value, $setting.Description
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "NTLM Settings:\n"
                table += "-" * 50 + "\n"
                command = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select-Object -Property NoLMHash | Format-Table -AutoSize"
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="ntlm-settings-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">NTLM Security Settings</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(table + output)}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "NTLM Settings:\n"
            table += "-" * 50 + "\n"
            command = "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select-Object -Property NoLMHash | Format-Table -AutoSize"
            return (table + run_powershell_command(command)).encode()

    def get_rdp_connections(self):
        # Use PowerShell to get RDP connections with HTML output
        command = """
        $rdpServers = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\Servers' -ErrorAction SilentlyContinue |
                     Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider

        # Create JSON data
        $serversJson = @(
            if ($rdpServers) {
                foreach ($server in $rdpServers.PSObject.Properties) {
                    @{
                        'Server' = $server.Name
                        'UsernameHint' = $server.Value
                    }
                }
            }
        ) | ConvertTo-Json

        # Create HTML table
        $htmlTable = @"
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>Server</th>
                        <th>Username Hint</th>
                    </tr>
                </thead>
                <tbody>
        "@

        if ($rdpServers) {
            foreach ($server in $rdpServers.PSObject.Properties) {
                $htmlTable += @"
                        <tr>
                            <td>$($server.Name)</td>
                            <td>$($server.Value)</td>
                        </tr>
        "@
            }
        } else {
            $htmlTable += @"
                        <tr>
                            <td colspan="2">No RDP connections found</td>
                        </tr>
        "@
        }

        $htmlTable += @"
                </tbody>
            </table>
        </div>
        "@

        # Create text table
        $textTable = "RDP Connections:`n"
        $textTable += "-" * 70 + "`n"

        if ($rdpServers) {
            $textTable += "Server                          Username Hint`n"
            $textTable += "-" * 70 + "`n"

            foreach ($server in $rdpServers.PSObject.Properties) {
                $textTable += "{0,-30} {1}`n" -f $server.Name, $server.Value
            }
        } else {
            $textTable += "No RDP connections found`n"
        }

        # Return both formats
        $result = @{
            Text = $textTable
            Html = $htmlTable
            Json = $serversJson
        } | ConvertTo-Json -Depth 3 -Compress

        Write-Output $result
        """

        result = run_powershell_command(command)

        try:
            # Try to parse the JSON result
            data = json.loads(result)

            # Return the appropriate format
            if 'web_display' in self.__dict__ and self.web_display:
                return data['Html'].encode()
            else:
                return data['Text'].encode()
        except:
            # Fallback to simple format if JSON parsing fails
            fallback_command = """
            Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\Servers' -ErrorAction SilentlyContinue |
            Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider |
            Format-Table -AutoSize
            """
            fallback_result = run_powershell_command(fallback_command)

            rdp_table = "RDP Connections:\n"
            rdp_table += "-" * 70 + "\n"
            rdp_table += fallback_result if fallback_result else "No RDP connections found"
            return rdp_table.encode()

    def get_secure_boot_info(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get secure boot and firmware information
            $secureBootInfo = @()

            try {
                # Get firmware type
                $computerInfo = Get-ComputerInfo -ErrorAction Stop
                $firmwareType = $computerInfo.BiosFirmwareType

                $secureBootInfo += @{
                    Name = "BIOS Type"
                    Value = if ($firmwareType -eq 2) { "UEFI" } else { "Legacy BIOS" }
                    Status = if ($firmwareType -eq 2) { "success" } else { "warning" }
                }

                # Get BIOS information
                $bios = Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue
                if ($bios) {
                    $secureBootInfo += @{
                        Name = "BIOS Manufacturer"
                        Value = $bios.Manufacturer
                        Status = "info"
                    }

                    $secureBootInfo += @{
                        Name = "BIOS Version"
                        Value = $bios.SMBIOSBIOSVersion
                        Status = "info"
                    }

                    $secureBootInfo += @{
                        Name = "BIOS Release Date"
                        Value = [System.Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate).ToString("yyyy-MM-dd")
                        Status = "info"
                    }
                }

                # Check secure boot status if UEFI
                if ($firmwareType -eq 2) {
                    try {
                        $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction Stop

                        $secureBootInfo += @{
                            Name = "Secure Boot"
                            Value = if ($secureBootStatus -eq $true) { "Enabled" } else { "Disabled" }
                            Status = if ($secureBootStatus -eq $true) { "success" } else { "danger" }
                        }
                    }
                    catch {
                        $secureBootInfo += @{
                            Name = "Secure Boot"
                            Value = "Unable to check status (may require elevated privileges)"
                            Status = "warning"
                        }
                    }

                    # Try to get more detailed secure boot information
                    try {
                        $secureBootPolicy = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State" -ErrorAction SilentlyContinue

                        if ($secureBootPolicy) {
                            $secureBootInfo += @{
                                Name = "Secure Boot Policy"
                                Value = if ($secureBootPolicy.PolicyPublisher) { $secureBootPolicy.PolicyPublisher } else { "Not available" }
                                Status = "info"
                            }
                        }
                    }
                    catch {
                        # Ignore errors for this optional information
                    }
                }
                else {
                    # Legacy BIOS - no secure boot
                    $secureBootInfo += @{
                        Name = "Secure Boot"
                        Value = "Not supported on Legacy BIOS systems"
                        Status = "warning"
                    }
                }

                # Get TPM information if available
                try {
                    $tpm = Get-Tpm -ErrorAction SilentlyContinue
                    if ($tpm) {
                        $secureBootInfo += @{
                            Name = "TPM Present"
                            Value = if ($tpm.TpmPresent) { "Yes" } else { "No" }
                            Status = if ($tpm.TpmPresent) { "success" } else { "warning" }
                        }

                        if ($tpm.TpmPresent) {
                            $secureBootInfo += @{
                                Name = "TPM Ready"
                                Value = if ($tpm.TpmReady) { "Yes" } else { "No" }
                                Status = if ($tpm.TpmReady) { "success" } else { "warning" }
                            }

                            $secureBootInfo += @{
                                Name = "TPM Enabled"
                                Value = if ($tpm.TpmEnabled) { "Yes" } else { "No" }
                                Status = if ($tpm.TpmEnabled) { "success" } else { "warning" }
                            }

                            $secureBootInfo += @{
                                Name = "TPM Activated"
                                Value = if ($tpm.TpmActivated) { "Yes" } else { "No" }
                                Status = if ($tpm.TpmActivated) { "success" } else { "warning" }
                            }
                        }
                    }
                }
                catch {
                    # TPM cmdlet might not be available on all systems
                    $secureBootInfo += @{
                        Name = "TPM Information"
                        Value = "Not available (requires elevated privileges or TPM module)"
                        Status = "info"
                    }
                }
            }
            catch {
                $secureBootInfo += @{
                    Name = "Error"
                    Value = $_.Exception.Message
                    Status = "danger"
                }
            }

            # Create HTML output with card-based layout
            $htmlOutput = @"
            <div class="secure-boot-container">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">Secure Boot & Firmware Information</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover mb-0">
                                <tbody>
"@

            foreach ($item in $secureBootInfo) {
                $name = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                $value = [System.Web.HttpUtility]::HtmlEncode($item.Value)

                # Set badge color based on status
                $badgeClass = switch ($item.Status) {
                    "success" { "bg-success" }
                    "warning" { "bg-warning text-dark" }
                    "danger" { "bg-danger" }
                    "info" { "bg-info text-dark" }
                    default { "bg-secondary" }
                }

                $htmlOutput += @"
                                    <tr>
                                        <td style="width: 30%"><strong>$name</strong></td>
                                        <td>
                                            <span class="badge $badgeClass">$value</span>
                                        </td>
                                    </tr>
"@
            }

            $htmlOutput += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Secure Boot Status:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($item in $secureBootInfo) {
                $textOutput += "{0,-25} : {1}`n" -f $item.Name, $item.Value
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "Secure Boot Status:\n"
                table += "-" * 70 + "\n"
                command = """
                $firmware = Get-ComputerInfo | Select-Object BiosFirmwareType
                if ($firmware.BiosFirmwareType -eq 2) {
                    "BIOS Type: UEFI"
                    try {
                        $status = Confirm-SecureBootUEFI
                        if ($status -eq $true) { "Secure Boot: Enabled" }
                        elseif ($status -eq $false) { "Secure Boot: Disabled" }
                        else { "Secure Boot: Status could not be determined" }
                    } catch {
                        "Secure Boot: Unable to check status (may require elevated privileges)"
                    }
                } else {
                    "BIOS Type: Legacy BIOS`nSecure Boot: Not supported on Legacy BIOS systems"
                }
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="secure-boot-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Secure Boot Information</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(table + (output or "Unable to determine system firmware type"))}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "Secure Boot Status:\n"
            table += "-" * 70 + "\n"
            command = """
            $firmware = Get-ComputerInfo | Select-Object BiosFirmwareType
            if ($firmware.BiosFirmwareType -eq 2) {
                "BIOS Type: UEFI"
                try {
                    $status = Confirm-SecureBootUEFI
                    if ($status -eq $true) { "Secure Boot: Enabled" }
                    elseif ($status -eq $false) { "Secure Boot: Disabled" }
                    else { "Secure Boot: Status could not be determined" }
                } catch {
                    "Secure Boot: Unable to check status (may require elevated privileges)"
                }
            } else {
                "BIOS Type: Legacy BIOS`nSecure Boot: Not supported on Legacy BIOS systems"
            }
            """
            output = run_powershell_command(command)
            return (table + (output or "Unable to determine system firmware type")).encode()

    def get_sysmon_config(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get Sysmon configuration information
            $sysmonInfo = @{
                "Service" = @()
                "Configuration" = @()
                "Rules" = @()
            }

            try {
                # Check if Sysmon service exists
                $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue

                if ($sysmonService) {
                    # Service information
                    $sysmonInfo["Service"] += @{
                        Name = "Service Name"
                        Value = $sysmonService.Name
                    }

                    $sysmonInfo["Service"] += @{
                        Name = "Display Name"
                        Value = $sysmonService.DisplayName
                    }

                    $sysmonInfo["Service"] += @{
                        Name = "Status"
                        Value = $sysmonService.Status
                    }

                    $sysmonInfo["Service"] += @{
                        Name = "Start Type"
                        Value = $sysmonService.StartType
                    }

                    # Get Sysmon driver information
                    $sysmonDrv = Get-Service -Name SysmonDrv -ErrorAction SilentlyContinue
                    if ($sysmonDrv) {
                        $sysmonInfo["Service"] += @{
                            Name = "Driver Status"
                            Value = $sysmonDrv.Status
                        }
                    }

                    # Get Sysmon version
                    try {
                        $sysmonExe = Get-Command sysmon.exe -ErrorAction SilentlyContinue
                        if ($sysmonExe) {
                            $fileInfo = Get-Item $sysmonExe.Source -ErrorAction SilentlyContinue
                            if ($fileInfo) {
                                $sysmonInfo["Service"] += @{
                                    Name = "Version"
                                    Value = $fileInfo.VersionInfo.ProductVersion
                                }

                                $sysmonInfo["Service"] += @{
                                    Name = "File Path"
                                    Value = $fileInfo.FullName
                                }
                            }
                        }
                    } catch {
                        # Ignore errors for this optional information
                    }

                    # Get Sysmon configuration parameters
                    $sysmonParams = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters' -ErrorAction SilentlyContinue
                    if ($sysmonParams) {
                        $paramProps = $sysmonParams.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }

                        foreach ($prop in $paramProps) {
                            $sysmonInfo["Configuration"] += @{
                                Name = $prop.Name
                                Value = $prop.Value
                            }
                        }
                    }

                    # Try to get Sysmon rules (this is a simplified approach)
                    try {
                        # Check if we can access the event log to see what events are being collected
                        $events = Get-WinEvent -ListProvider "Microsoft-Windows-Sysmon" -ErrorAction SilentlyContinue
                        if ($events) {
                            $sysmonInfo["Rules"] += @{
                                Name = "Event Provider"
                                Value = $events.Name
                            }

                            $sysmonInfo["Rules"] += @{
                                Name = "Log Name"
                                Value = "Microsoft-Windows-Sysmon/Operational"
                            }

                            # Get event IDs that Sysmon is configured to collect
                            $eventTypes = @(
                                @{ ID = 1; Name = "Process Creation" },
                                @{ ID = 2; Name = "File Creation Time" },
                                @{ ID = 3; Name = "Network Connection" },
                                @{ ID = 4; Name = "Sysmon Service State Change" },
                                @{ ID = 5; Name = "Process Termination" },
                                @{ ID = 6; Name = "Driver Load" },
                                @{ ID = 7; Name = "Image Load" },
                                @{ ID = 8; Name = "CreateRemoteThread" },
                                @{ ID = 9; Name = "RawAccessRead" },
                                @{ ID = 10; Name = "ProcessAccess" },
                                @{ ID = 11; Name = "FileCreate" },
                                @{ ID = 12; Name = "RegistryEvent (Object create and delete)" },
                                @{ ID = 13; Name = "RegistryEvent (Value Set)" },
                                @{ ID = 14; Name = "RegistryEvent (Key and Value Rename)" },
                                @{ ID = 15; Name = "FileCreateStreamHash" },
                                @{ ID = 16; Name = "ServiceConfigurationChange" },
                                @{ ID = 17; Name = "PipeEvent (Pipe Created)" },
                                @{ ID = 18; Name = "PipeEvent (Pipe Connected)" },
                                @{ ID = 19; Name = "WmiEvent (WmiEventFilter activity detected)" },
                                @{ ID = 20; Name = "WmiEvent (WmiEventConsumer activity detected)" },
                                @{ ID = 21; Name = "WmiEvent (WmiEventConsumerToFilter activity detected)" },
                                @{ ID = 22; Name = "DNSEvent (DNS query)" },
                                @{ ID = 23; Name = "FileDelete (File Delete archived)" },
                                @{ ID = 24; Name = "ClipboardChange (New content in the clipboard)" },
                                @{ ID = 25; Name = "ProcessTampering (Process image change)" },
                                @{ ID = 26; Name = "FileDeleteDetected (File Delete logged)" },
                                @{ ID = 27; Name = "FileBlockExecutable (Executable blocked from running)" },
                                @{ ID = 28; Name = "FileBlockShredding (File shredding prevented)" }
                            )

                            foreach ($eventType in $eventTypes) {
                                # Check if we can find any events of this type in the last day
                                # This is just a heuristic to guess which events are being collected
                                try {
                                    $query = "*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and EventID=$($eventType.ID)]]"
                                    $count = (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath $query -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object).Count

                                    $status = if ($count -gt 0) { "Active" } else { "No recent events" }

                                    $sysmonInfo["Rules"] += @{
                                        Name = "Event ID $($eventType.ID)"
                                        Value = "$($eventType.Name) - $status"
                                    }
                                } catch {
                                    # Skip if we can't query this event type
                                }
                            }
                        }
                    } catch {
                        $sysmonInfo["Rules"] += @{
                            Name = "Rules Information"
                            Value = "Could not access Sysmon event log (requires elevated privileges)"
                        }
                    }
                } else {
                    # Sysmon not installed
                    $sysmonInfo["Service"] += @{
                        Name = "Status"
                        Value = "Sysmon is not installed on this system"
                    }
                }
            } catch {
                $sysmonInfo["Service"] += @{
                    Name = "Error"
                    Value = $_.Exception.Message
                }
            }

            # Create HTML output with card-based layout
            $htmlOutput = @"
            <div class="sysmon-config-container">
                <div class="row">
"@

            # Process each section
            foreach ($section in $sysmonInfo.Keys) {
                $items = $sysmonInfo[$section]
                if ($items.Count -gt 0) {
                    $htmlOutput += @"
                    <div class="col-md-12 mb-4">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0">Sysmon $section</h5>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th style="width: 30%">Setting</th>
                                                <th>Value</th>
                                            </tr>
                                        </thead>
                                        <tbody>
"@

                    foreach ($item in $items) {
                        $name = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                        $value = [System.Web.HttpUtility]::HtmlEncode($item.Value)

                        $htmlOutput += @"
                                            <tr>
                                                <td><strong>$name</strong></td>
                                                <td>$value</td>
                                            </tr>
"@
                    }

                    $htmlOutput += @"
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
"@
                }
            }

            $htmlOutput += @"
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "Sysmon Configuration:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($section in $sysmonInfo.Keys) {
                $items = $sysmonInfo[$section]
                if ($items.Count -gt 0) {
                    $textOutput += "`n$section:`n"
                    $textOutput += "-" * 30 + "`n"

                    foreach ($item in $items) {
                        $textOutput += "{0,-30} : {1}`n" -f $item.Name, $item.Value
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "Sysmon Configuration:\n"
                table += "-" * 70 + "\n"
                command = """
                $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
                if ($sysmonService) {
                    "Service Status: $($sysmonService.Status)"
                    ""
                    "Configuration Details:"
                    Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters' -ErrorAction SilentlyContinue |
                    Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider |
                    Format-Table -AutoSize
                } else {
                    "Sysmon is not installed on this system"
                }
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="sysmon-config-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">Sysmon Configuration</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(table + (output or "No Sysmon configuration found"))}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "Sysmon Configuration:\n"
            table += "-" * 70 + "\n"
            command = """
            $sysmonService = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
            if ($sysmonService) {
                "Service Status: $($sysmonService.Status)"
                ""
                "Configuration Details:"
                Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters' -ErrorAction SilentlyContinue |
                Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider |
                Format-Table -AutoSize
            } else {
                "Sysmon is not installed on this system"
            }
            """
            output = run_powershell_command(command)
            return (table + (output or "No Sysmon configuration found")).encode()

    def get_uac_policies(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Get UAC policy information
            $uacPolicies = @()

            try {
                $policies = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop

                # ConsentPromptBehaviorAdmin - Controls behavior of the elevation prompt for administrators
                $adminPromptValue = $policies.ConsentPromptBehaviorAdmin
                $adminPromptDesc = switch ($adminPromptValue) {
                    0 { "Elevate without prompting" }
                    1 { "Prompt for credentials on the secure desktop" }
                    2 { "Prompt for consent on the secure desktop" }
                    3 { "Prompt for credentials" }
                    4 { "Prompt for consent" }
                    5 { "Prompt for consent for non-Windows binaries" }
                    default { "Unknown setting" }
                }
                $uacPolicies += @{
                    Name = "ConsentPromptBehaviorAdmin"
                    Value = "$adminPromptValue - $adminPromptDesc"
                    Description = "Controls behavior of the elevation prompt for administrators"
                    Status = if ($adminPromptValue -eq 0) { "danger" } elseif ($adminPromptValue -eq 5) { "success" } else { "warning" }
                }

                # ConsentPromptBehaviorUser - Controls behavior of the elevation prompt for standard users
                $userPromptValue = $policies.ConsentPromptBehaviorUser
                $userPromptDesc = switch ($userPromptValue) {
                    0 { "Automatically deny elevation requests" }
                    1 { "Prompt for credentials on the secure desktop" }
                    3 { "Prompt for credentials" }
                    default { "Unknown setting" }
                }
                $uacPolicies += @{
                    Name = "ConsentPromptBehaviorUser"
                    Value = "$userPromptValue - $userPromptDesc"
                    Description = "Controls behavior of the elevation prompt for standard users"
                    Status = "info"
                }

                # EnableLUA - User Account Control: Run all administrators in Admin Approval Mode
                $enableLuaValue = $policies.EnableLUA
                $enableLuaDesc = if ($enableLuaValue -eq 1) { "Enabled (UAC is on)" } else { "Disabled (UAC is off)" }
                $uacPolicies += @{
                    Name = "EnableLUA"
                    Value = "$enableLuaValue - $enableLuaDesc"
                    Description = "User Account Control: Run all administrators in Admin Approval Mode"
                    Status = if ($enableLuaValue -eq 1) { "success" } else { "danger" }
                }

                # PromptOnSecureDesktop - User Account Control: Switch to the secure desktop when prompting for elevation
                $secureDesktopValue = $policies.PromptOnSecureDesktop
                $secureDesktopDesc = if ($secureDesktopValue -eq 1) { "Enabled" } else { "Disabled" }
                $uacPolicies += @{
                    Name = "PromptOnSecureDesktop"
                    Value = "$secureDesktopValue - $secureDesktopDesc"
                    Description = "User Account Control: Switch to the secure desktop when prompting for elevation"
                    Status = if ($secureDesktopValue -eq 1) { "success" } else { "warning" }
                }

                # EnableInstallerDetection - User Account Control: Detect application installations and prompt for elevation
                $installerDetectionValue = $policies.EnableInstallerDetection
                $installerDetectionDesc = if ($installerDetectionValue -eq 1) { "Enabled" } else { "Disabled" }
                $uacPolicies += @{
                    Name = "EnableInstallerDetection"
                    Value = "$installerDetectionValue - $installerDetectionDesc"
                    Description = "User Account Control: Detect application installations and prompt for elevation"
                    Status = if ($installerDetectionValue -eq 1) { "success" } else { "warning" }
                }

                # EnableSecureUIAPaths - User Account Control: Only elevate UIAccess applications that are installed in secure locations
                $secureUiaValue = $policies.EnableSecureUIAPaths
                $secureUiaDesc = if ($secureUiaValue -eq 1) { "Enabled" } else { "Disabled" }
                $uacPolicies += @{
                    Name = "EnableSecureUIAPaths"
                    Value = "$secureUiaValue - $secureUiaDesc"
                    Description = "User Account Control: Only elevate UIAccess applications that are installed in secure locations"
                    Status = if ($secureUiaValue -eq 1) { "success" } else { "warning" }
                }

                # EnableVirtualization - User Account Control: Virtualize file and registry write failures to per-user locations
                $virtualizationValue = $policies.EnableVirtualization
                $virtualizationDesc = if ($virtualizationValue -eq 1) { "Enabled" } else { "Disabled" }
                $uacPolicies += @{
                    Name = "EnableVirtualization"
                    Value = "$virtualizationValue - $virtualizationDesc"
                    Description = "User Account Control: Virtualize file and registry write failures to per-user locations"
                    Status = if ($virtualizationValue -eq 1) { "success" } else { "warning" }
                }

                # FilterAdministratorToken - User Account Control: Admin Approval Mode for the built-in Administrator account
                if ($null -ne $policies.FilterAdministratorToken) {
                    $filterAdminValue = $policies.FilterAdministratorToken
                    $filterAdminDesc = if ($filterAdminValue -eq 1) { "Enabled" } else { "Disabled" }
                    $uacPolicies += @{
                        Name = "FilterAdministratorToken"
                        Value = "$filterAdminValue - $filterAdminDesc"
                        Description = "User Account Control: Admin Approval Mode for the built-in Administrator account"
                        Status = if ($filterAdminValue -eq 1) { "success" } else { "warning" }
                    }
                }

                # Check for additional UAC-related settings
                $additionalProps = $policies.PSObject.Properties | Where-Object {
                    $_.Name -match 'UAC|LocalAccount|Elevation|Admin' -and
                    $_.Name -notmatch '^PS' -and
                    $_.Name -notin @('ConsentPromptBehaviorAdmin', 'ConsentPromptBehaviorUser', 'EnableInstallerDetection',
                                    'EnableLUA', 'EnableSecureUIAPaths', 'EnableVirtualization', 'PromptOnSecureDesktop',
                                    'FilterAdministratorToken')
                }

                foreach ($prop in $additionalProps) {
                    $uacPolicies += @{
                        Name = $prop.Name
                        Value = $prop.Value
                        Description = "Additional UAC-related setting"
                        Status = "info"
                    }
                }

                # Calculate overall UAC security level
                $uacLevel = "Unknown"
                if ($policies.EnableLUA -eq 0) {
                    $uacLevel = "Off"
                    $uacLevelStatus = "danger"
                } elseif ($policies.ConsentPromptBehaviorAdmin -eq 0) {
                    $uacLevel = "Never notify"
                    $uacLevelStatus = "danger"
                } elseif ($policies.ConsentPromptBehaviorAdmin -eq 5 -and $policies.PromptOnSecureDesktop -eq 1) {
                    $uacLevel = "Always notify"
                    $uacLevelStatus = "success"
                } elseif ($policies.ConsentPromptBehaviorAdmin -eq 5 -and $policies.PromptOnSecureDesktop -eq 0) {
                    $uacLevel = "Always notify (without secure desktop)"
                    $uacLevelStatus = "warning"
                } elseif ($policies.ConsentPromptBehaviorAdmin -eq 2 -and $policies.PromptOnSecureDesktop -eq 1) {
                    $uacLevel = "Notify only when apps try to make changes (default)"
                    $uacLevelStatus = "success"
                } elseif ($policies.ConsentPromptBehaviorAdmin -eq 2 -and $policies.PromptOnSecureDesktop -eq 0) {
                    $uacLevel = "Notify only when apps try to make changes (without secure desktop)"
                    $uacLevelStatus = "warning"
                }

                $uacPolicies = @(@{
                    Name = "UAC Security Level"
                    Value = $uacLevel
                    Description = "Overall User Account Control security level"
                    Status = $uacLevelStatus
                }) + $uacPolicies
            }
            catch {
                $uacPolicies += @{
                    Name = "Error"
                    Value = $_.Exception.Message
                    Description = "Error accessing UAC policies"
                    Status = "danger"
                }
            }

            # Create HTML output with card-based layout
            $htmlOutput = @"
            <div class="uac-policies-container">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">User Account Control (UAC) Policies</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th style="width: 25%">Setting</th>
                                        <th style="width: 25%">Value</th>
                                        <th style="width: 50%">Description</th>
                                    </tr>
                                </thead>
                                <tbody>
"@

            foreach ($policy in $uacPolicies) {
                $name = [System.Web.HttpUtility]::HtmlEncode($policy.Name)
                $value = [System.Web.HttpUtility]::HtmlEncode($policy.Value)
                $description = [System.Web.HttpUtility]::HtmlEncode($policy.Description)

                # Set badge color based on status
                $badgeClass = switch ($policy.Status) {
                    "success" { "bg-success" }
                    "warning" { "bg-warning text-dark" }
                    "danger" { "bg-danger" }
                    "info" { "bg-info text-dark" }
                    default { "bg-secondary" }
                }

                $htmlOutput += @"
                                    <tr>
                                        <td><strong>$name</strong></td>
                                        <td><span class="badge $badgeClass">$value</span></td>
                                        <td><em>$description</em></td>
                                    </tr>
"@
            }

            $htmlOutput += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
"@

            # Create text output for terminal
            $textOutput = "UAC Policies:`n"
            $textOutput += "-" * 70 + "`n"
            $textOutput += "Setting                         Value                           Description`n"
            $textOutput += "-" * 100 + "`n"

            foreach ($policy in $uacPolicies) {
                $textOutput += "{0,-30} {1,-30} {2}`n" -f $policy.Name, $policy.Value, $policy.Description
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "UAC Policies:\n"
                table += "-" * 70 + "\n"
                command = """
                $policies = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop
                $props = @(
                    'ConsentPromptBehaviorAdmin',
                    'ConsentPromptBehaviorUser',
                    'EnableInstallerDetection',
                    'EnableLUA',
                    'EnableSecureUIAPaths',
                    'EnableVirtualization',
                    'PromptOnSecureDesktop'
                )
                foreach ($prop in $props) {
                    if ($policies.$prop -ne $null) {
                        "$prop : $($policies.$prop)"
                    }
                }
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="uac-policies-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">User Account Control (UAC) Policies</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(table + (output or "No UAC policies found. This may indicate a permissions issue."))}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "UAC Policies:\n"
            table += "-" * 70 + "\n"
            command = """
            $policies = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop
            $props = @(
                'ConsentPromptBehaviorAdmin',
                'ConsentPromptBehaviorUser',
                'EnableInstallerDetection',
                'EnableLUA',
                'EnableSecureUIAPaths',
                'EnableVirtualization',
                'PromptOnSecureDesktop'
            )
            foreach ($prop in $props) {
                if ($policies.$prop -ne $null) {
                    "$prop : $($policies.$prop)"
                }
            }
            """
            output = run_powershell_command(command)
            return (table + (output or "No UAC policies found. This may indicate a permissions issue.")).encode()

    def get_powershell_history(self):
        if 'web_display' in self.__dict__ and self.web_display:
            command = """
            # Add System.Web for HTML encoding
            Add-Type -AssemblyName System.Web

            # Create data structure to hold all history information
            $historyData = @{
                "Current Session" = @()
                "PSReadLine History" = @()
                "Transcript Files" = @()
            }

            # Get current session history
            try {
                $history = Get-History -ErrorAction Stop
                if ($history) {
                    foreach ($entry in $history) {
                        $historyData["Current Session"] += @{
                            Id = $entry.Id
                            Command = $entry.CommandLine
                            ExecutionTime = $entry.StartExecutionTime.ToString("yyyy-MM-dd HH:mm:ss")
                            Duration = if ($entry.EndExecutionTime) {
                                [math]::Round(($entry.EndExecutionTime - $entry.StartExecutionTime).TotalSeconds, 2)
                            } else { 0 }
                        }
                    }
                }
            } catch {
                # Just continue if this fails
            }

            # Get PSReadLine history
            try {
                $historyPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath
                if (Test-Path $historyPath) {
                    $content = Get-Content $historyPath -Tail 200 -ErrorAction Stop
                    $id = 1
                    foreach ($line in $content) {
                        if ($line.Trim()) {
                            $historyData["PSReadLine History"] += @{
                                Id = $id
                                Command = $line
                                Source = $historyPath
                            }
                            $id++
                        }
                    }
                }
            } catch {
                # Just continue if this fails
            }

            # Get transcripts if available
            try {
                $transcriptPath = "$env:USERPROFILE\\Documents\\PowerShell\\Transcripts"
                if (Test-Path $transcriptPath) {
                    $transcripts = Get-ChildItem $transcriptPath -File -ErrorAction Stop |
                                  Sort-Object LastWriteTime -Descending

                    foreach ($transcript in $transcripts) {
                        $historyData["Transcript Files"] += @{
                            Name = $transcript.Name
                            Path = $transcript.FullName
                            LastModified = $transcript.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            SizeKB = [math]::Round($transcript.Length/1KB, 2)
                        }
                    }
                }
            } catch {
                # Just continue if this fails
            }

            # Create HTML output with cards for each history type
            $htmlOutput = @"
            <div class="powershell-history-container">
                <div class="mb-4">
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control" id="command-search" placeholder="Search PowerShell commands..." onkeyup="filterCommands()">
                        <button class="btn btn-outline-secondary" type="button" onclick="clearCommandSearch()">Clear</button>
                    </div>
                    <div class="form-text">Search by command text</div>
                </div>

                <script>
                function filterCommands() {
                    const searchText = document.getElementById('command-search').value.toLowerCase();
                    const rows = document.querySelectorAll('.command-row');

                    let visibleCategories = new Set();

                    // First pass: determine which rows should be visible
                    rows.forEach(row => {
                        const command = row.querySelector('.command-text').textContent.toLowerCase();

                        if (searchText === '' || command.includes(searchText)) {
                            row.style.display = '';
                            // Add this row's category to the visible set
                            const categoryId = row.closest('.history-category').id;
                            visibleCategories.add(categoryId);
                        } else {
                            row.style.display = 'none';
                        }
                    });

                    // Second pass: show/hide category cards based on whether they have visible rows
                    document.querySelectorAll('.history-category').forEach(category => {
                        if (visibleCategories.has(category.id)) {
                            category.style.display = '';
                        } else {
                            category.style.display = 'none';
                        }
                    });

                    // Update the count of visible commands
                    updateVisibleCount();
                }

                function updateVisibleCount() {
                    const totalVisible = document.querySelectorAll('.command-row:not([style*="display: none"])').length;
                    const totalCommands = document.querySelectorAll('.command-row').length;
                    document.getElementById('visible-count').textContent = totalVisible;
                    document.getElementById('total-count').textContent = totalCommands;
                }

                function clearCommandSearch() {
                    document.getElementById('command-search').value = '';
                    filterCommands();
                }

                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(function() {
                        // Show a temporary success message
                        const tooltip = document.createElement('div');
                        tooltip.className = 'copy-tooltip';
                        tooltip.textContent = 'Copied!';
                        document.body.appendChild(tooltip);

                        // Position near mouse
                        tooltip.style.top = (event.clientY - 30) + 'px';
                        tooltip.style.left = event.clientX + 'px';

                        // Remove after a short delay
                        setTimeout(() => {
                            tooltip.remove();
                        }, 1000);
                    });
                }
                </script>

                <style>
                .copy-tooltip {
                    position: fixed;
                    background: rgba(0,0,0,0.7);
                    color: white;
                    padding: 5px 10px;
                    border-radius: 4px;
                    z-index: 1000;
                    animation: fadeOut 1s ease-out;
                }

                @keyframes fadeOut {
                    0% { opacity: 1; }
                    70% { opacity: 1; }
                    100% { opacity: 0; }
                }

                .command-text {
                    font-family: monospace;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
                </style>

                <div class="alert alert-info mb-3">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>
                            <i class="fas fa-info-circle me-2"></i>
                            Showing <span id="visible-count">0</span> of <span id="total-count">0</span> PowerShell commands
                        </span>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="document.querySelectorAll('.history-category .collapse').forEach(el => el.classList.add('show'))">Expand All</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="document.querySelectorAll('.history-category .collapse').forEach(el => el.classList.remove('show'))">Collapse All</button>
                        </div>
                    </div>
                </div>

                <div class="row">
"@

            # Process each history type
            $categoryOrder = @("Current Session", "PSReadLine History", "Transcript Files")
            foreach ($category in $categoryOrder) {
                $items = $historyData[$category]
                $categoryId = $category.Replace(" ", "-").ToLower()
                $collapseId = "collapse-$categoryId"

                # Choose card color based on category
                $cardColor = switch ($category) {
                    "Current Session" { "bg-primary" }
                    "PSReadLine History" { "bg-success" }
                    "Transcript Files" { "bg-info" }
                    default { "bg-secondary" }
                }

                $htmlOutput += @"
                    <div class="col-md-12 mb-4 history-category" id="category-$categoryId">
                        <div class="card">
                            <div class="card-header $cardColor text-white">
                                <div class="d-flex justify-content-between align-items-center" data-bs-toggle="collapse" data-bs-target="#$collapseId" aria-expanded="true" style="cursor: pointer;">
                                    <h5 class="mb-0">$category</h5>
                                    <div>
                                        <span class="badge bg-light text-dark me-2">$($items.Count) items</span>
                                        <i class="fas fa-chevron-down"></i>
                                    </div>
                                </div>
"@

                # Add source path for PSReadLine history
                if ($category -eq "PSReadLine History" -and $items.Count -gt 0) {
                    $sourcePath = $items[0].Source
                    $htmlOutput += @"
                                <small class="text-white-50">Source: $([System.Web.HttpUtility]::HtmlEncode($sourcePath))</small>
"@
                }

                $htmlOutput += @"
                            </div>
                            <div class="collapse show" id="$collapseId">
"@

                if ($items.Count -eq 0) {
                    $htmlOutput += @"
                                <div class="card-body">
                                    <div class="alert alert-info mb-0">
                                        <i class="fas fa-info-circle me-2"></i>
                                        No $category data available
                                    </div>
                                </div>
"@
                } else {
                    if ($category -eq "Transcript Files") {
                        # Display transcripts as a table
                        $htmlOutput += @"
                                <div class="card-body p-0">
                                    <div class="table-responsive">
                                        <table class="table table-striped table-hover mb-0">
                                            <thead class="table-light">
                                                <tr>
                                                    <th>Name</th>
                                                    <th>Last Modified</th>
                                                    <th>Size (KB)</th>
                                                </tr>
                                            </thead>
                                            <tbody>
"@

                        foreach ($transcript in $items) {
                            $name = [System.Web.HttpUtility]::HtmlEncode($transcript.Name)
                            $path = [System.Web.HttpUtility]::HtmlEncode($transcript.Path)
                            $lastModified = [System.Web.HttpUtility]::HtmlEncode($transcript.LastModified)
                            $sizeKB = $transcript.SizeKB

                            $htmlOutput += @"
                                                <tr>
                                                    <td title="$path">$name</td>
                                                    <td>$lastModified</td>
                                                    <td>$sizeKB</td>
                                                </tr>
"@
                        }

                        $htmlOutput += @"
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
"@
                    } else {
                        # Display commands as a list with copy buttons
                        $htmlOutput += @"
                                <div class="card-body p-0">
                                    <div class="list-group list-group-flush">
"@

                        foreach ($item in $items) {
                            $id = $item.Id
                            $command = [System.Web.HttpUtility]::HtmlEncode($item.Command)
                            $commandJs = $item.Command.Replace('"', '\"').Replace("'", "\'").Replace("`n", "\n").Replace("`r", "\r")

                            $htmlOutput += @"
                                        <div class="list-group-item command-row">
                                            <div class="d-flex justify-content-between align-items-start">
                                                <div class="me-2">
                                                    <span class="badge bg-secondary">$id</span>
                                                </div>
                                                <div class="flex-grow-1 command-text">$command</div>
                                                <div class="ms-2">
                                                    <button class="btn btn-sm btn-outline-secondary" onclick="copyToClipboard('$commandJs')">
                                                        <i class="fas fa-copy"></i>
                                                    </button>
                                                </div>
                                            </div>
"@

                            # Add execution time for current session
                            if ($category -eq "Current Session" -and $item.ExecutionTime) {
                                $executionTime = [System.Web.HttpUtility]::HtmlEncode($item.ExecutionTime)
                                $duration = $item.Duration

                                $htmlOutput += @"
                                            <div class="mt-2 small text-muted">
                                                <span title="Execution Time">
                                                    <i class="fas fa-clock me-1"></i>$executionTime
                                                </span>
                                                <span class="ms-3" title="Duration in seconds">
                                                    <i class="fas fa-stopwatch me-1"></i>$duration s
                                                </span>
                                            </div>
"@
                            }

                            $htmlOutput += @"
                                        </div>
"@
                        }

                        $htmlOutput += @"
                                    </div>
                                </div>
"@
                    }
                }

                $htmlOutput += @"
                            </div>
                        </div>
                    </div>
"@
            }

            $htmlOutput += @"
                </div>

                <script>
                    // Initialize counts
                    document.addEventListener('DOMContentLoaded', function() {
                        const totalCommands = document.querySelectorAll('.command-row').length;
                        document.getElementById('visible-count').textContent = totalCommands;
                        document.getElementById('total-count').textContent = totalCommands;
                    });
                </script>
            </div>
"@

            # Create text output for terminal
            $textOutput = "PowerShell Command History:`n"
            $textOutput += "-" * 70 + "`n"

            foreach ($category in $categoryOrder) {
                $items = $historyData[$category]

                $textOutput += "`n$category ($($items.Count) items):`n"
                $textOutput += "-" * 50 + "`n"

                if ($items.Count -eq 0) {
                    $textOutput += "No $category data available`n"
                } else {
                    if ($category -eq "Transcript Files") {
                        # Display transcripts as a table
                        $textOutput += "Name                           Last Modified             Size (KB)`n"
                        $textOutput += "-" * 70 + "`n"

                        foreach ($transcript in $items) {
                            $name = if ($transcript.Name.Length -gt 30) { $transcript.Name.Substring(0, 27) + "..." } else { $transcript.Name }
                            $textOutput += "{0,-30} {1,-25} {2}`n" -f $name, $transcript.LastModified, $transcript.SizeKB
                        }
                    } else {
                        # Display commands
                        foreach ($item in $items) {
                            $textOutput += "{0,3}> {1}`n" -f $item.Id, $item.Command

                            # Add execution time for current session
                            if ($category -eq "Current Session" -and $item.ExecutionTime) {
                                $textOutput += "     [Executed: $($item.ExecutionTime), Duration: $($item.Duration) s]`n"
                            }

                            $textOutput += "`n"
                        }
                    }
                }
            }

            # Return both formats
            $result = @{
                Text = $textOutput
                Html = $htmlOutput
            } | ConvertTo-Json -Depth 4 -Compress

            Write-Output $result
            """

            result = run_powershell_command(command, timeout=30)

            try:
                # Try to parse the JSON result
                data = json.loads(result)

                # Return the HTML format
                return data['Html'].encode()
            except Exception as e:
                # Fallback to original method if PowerShell approach fails
                table = "PowerShell Command History:\n"
                table += "-" * 70 + "\n"
                command = """
                # Get current session history
                Write-Output "Current Session History:"
                Write-Output ("-" * 200)
                try {
                    $history = Get-History
                    if ($history) {
                        $history | Format-Table Id, @{
                            Label = 'Command'
                            Expression = { $_.CommandLine }
                        }, @{
                            Label = 'Execution Time'
                            Expression = { $_.StartExecutionTime }
                        } -AutoSize -Wrap
                    } else {
                        "No commands in current session"
                    }
                } catch {
                    "No history available in current session"
                }

                # Get PSReadLine history
                Write-Output "`nPSReadLine History File:"
                Write-Output ("-" * 200)
                try {
                    $historyPath = (Get-PSReadLineOption).HistorySavePath
                    if (Test-Path $historyPath) {
                        Write-Output "Location: $historyPath"
                        Write-Output ("-" * 200)

                        # Get last 50 commands with numbering
                        $content = Get-Content $historyPath -Tail 200
                        for ($i = 0; $i -lt $content.Count; $i++) {
                            if ($content[$i].Trim()) {
                                "{0,3}> {1}" -f ($i + 1), $content[$i]
                            }
                        }
                    } else {
                        "PSReadLine history file not found"
                    }
                } catch {
                    "Unable to access PSReadLine history"
                }

                # Get transcripts if available
                Write-Output "`nPowerShell Transcript Files:"
                Write-Output ("-" * 50)
                try {
                    $transcriptPath = "$env:USERPROFILE\\Documents\\PowerShell\\Transcripts"
                    if (Test-Path $transcriptPath) {
                        Get-ChildItem $transcriptPath -File |
                        Sort-Object LastWriteTime -Descending |
                        Format-Table @{
                            Label = 'Name'
                            Expression = { $_.Name }
                        }, @{
                            Label = 'Last Modified'
                            Expression = { $_.LastWriteTime }
                        }, @{
                            Label = 'Size (KB)'
                            Expression = { [math]::Round($_.Length/1KB, 2) }
                        } -AutoSize
                    } else {
                        "No transcript files found"
                    }
                } catch {
                    "Unable to access transcript files"
                }
                """
                output = run_powershell_command(command)

                # Format as HTML
                html_output = f"""
                <div class="powershell-history-container">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0">PowerShell Command History</h5>
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 500px; overflow-y: auto;">{html.escape(output or "No PowerShell history found")}</pre>
                        </div>
                    </div>
                </div>
                """

                return html_output.encode()
        else:
            # For terminal display, use the original method
            table = "PowerShell Command History:\n"
            table += "-" * 70 + "\n"
            command = """
            # Get current session history
            Write-Output "Current Session History:"
            Write-Output ("-" * 200)
            try {
                $history = Get-History
                if ($history) {
                    $history | Format-Table Id, @{
                        Label = 'Command'
                        Expression = { $_.CommandLine }
                    }, @{
                        Label = 'Execution Time'
                        Expression = { $_.StartExecutionTime }
                    } -AutoSize -Wrap
                } else {
                    "No commands in current session"
                }
            } catch {
                "No history available in current session"
            }

            # Get PSReadLine history
            Write-Output "`nPSReadLine History File:"
            Write-Output ("-" * 200)
            try {
                $historyPath = (Get-PSReadLineOption).HistorySavePath
                if (Test-Path $historyPath) {
                    Write-Output "Location: $historyPath"
                    Write-Output ("-" * 200)

                    # Get last 50 commands with numbering
                    $content = Get-Content $historyPath -Tail 200
                    for ($i = 0; $i -lt $content.Count; $i++) {
                        if ($content[$i].Trim()) {
                            "{0,3}> {1}" -f ($i + 1), $content[$i]
                        }
                    }
                } else {
                    "PSReadLine history file not found"
                }
            } catch {
                "Unable to access PSReadLine history"
            }

            # Get transcripts if available
            Write-Output "`nPowerShell Transcript Files:"
            Write-Output ("-" * 50)
            try {
                $transcriptPath = "$env:USERPROFILE\\Documents\\PowerShell\\Transcripts"
                if (Test-Path $transcriptPath) {
                    Get-ChildItem $transcriptPath -File |
                    Sort-Object LastWriteTime -Descending |
                    Format-Table @{
                        Label = 'Name'
                        Expression = { $_.Name }
                    }, @{
                        Label = 'Last Modified'
                        Expression = { $_.LastWriteTime }
                    }, @{
                        Label = 'Size (KB)'
                        Expression = { [math]::Round($_.Length/1KB, 2) }
                    } -AutoSize
                } else {
                    "No transcript files found"
                }
            } catch {
                "Unable to access transcript files"
            }
            """
            output = run_powershell_command(command)
            if not output:
                output = "No PowerShell history found"
            return (table + output).encode()




class NetworkInfo:
    def __init__(self, routerip="192.168.29.1", network="192.168.29.0/24", iface=None, web_display=False):
        self.routerip = routerip
        self.network = network
        self.iface = iface if iface else conf.iface
        self.web_display = web_display

    def arp_scan(self):
        # Perform ARP scan
        devices = []
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network), timeout=5, iface=self.iface, verbose=False)

        for _, received in ans:
            mac = received[ARP].hwsrc
            ip = received.psrc
            try:
                vendor = MacLookup().lookup(mac)
            except VendorNotFoundError:
                vendor = "Unknown"

            devices.append({
                'IP Address': ip,
                'MAC Address': mac,
                'Vendor': vendor
            })

        # Create HTML table
        html_output = """
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody>
        """

        if devices:
            for device in devices:
                html_output += f"""
                    <tr>
                        <td>{html.escape(device['IP Address'])}</td>
                        <td>{html.escape(device['MAC Address'])}</td>
                        <td>{html.escape(device['Vendor'])}</td>
                    </tr>
                """
        else:
            html_output += """
                <tr>
                    <td colspan="3">No devices found</td>
                </tr>
            """

        html_output += """
                </tbody>
            </table>
        </div>
        """

        # Create text table
        text_output = "Network Device Discovery:\n"
        text_output += "-" * 70 + "\n"
        text_output += f"{'IP Address':<20} {'MAC Address':<20} {'Vendor'}\n"
        text_output += "-" * 70 + "\n"

        if devices:
            for device in devices:
                text_output += f"{device['IP Address']:<20} {device['MAC Address']:<20} {device['Vendor']}\n"
        else:
            text_output += "No devices found\n"

        # Check if this is a web request
        if hasattr(self, 'web_display') and self.web_display:
            return html_output.encode()
        else:
            return text_output.encode()

    def dns_cache(self):
        try:
            output = subprocess.check_output(["ipconfig", "/displaydns"], text=True)
            return output.encode()
        except subprocess.CalledProcessError as e:
            return f"Error retrieving DNS cache: {str(e)}".encode()

    def windows_network_profile(self):
        table = "Network Configuration:\n"
        table += "=" * 70 + "\n\n"

        try:
            # Network Adapters
            table += "Network Adapters:\n"
            table += "-" * 70 + "\n"
            net_adapters = subprocess.check_output(["powershell", "Get-NetAdapter | Format-Table -AutoSize"], text=True)
            table += net_adapters + "\n"

            # IP Configuration
            table += "IP Configuration:\n"
            table += "-" * 70 + "\n"
            ipconfig = subprocess.check_output(["ipconfig", "/all"], text=True)
            table += ipconfig + "\n"

            # WLAN Profiles
            table += "Wireless Profiles:\n"
            table += "-" * 70 + "\n"
            wlan = subprocess.check_output(["netsh", "wlan", "show", "profile"], text=True)
            table += wlan
        except subprocess.CalledProcessError as e:
            table += f"Error: {str(e)}\n"

        return table.encode()

    def network_shares(self):
        table = "Network Shares:\n"
        table += "-" * 70 + "\n"
        try:
            shares = subprocess.check_output(["powershell", "Get-SmbShare | Format-Table -AutoSize"], text=True)
            table += shares
        except subprocess.CalledProcessError as e:
            table += f"Error: {str(e)}\n"
        return table.encode()

    def tcp_udp_connections(self):
        # Use PowerShell to get network connections with HTML output
        command = """
        $connections = Get-NetTCPConnection |
        ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                ProcessName = $process.ProcessName
                PID = $_.OwningProcess
            }
        }

        # Create JSON data
        $connectionsJson = @(
            foreach ($conn in $connections) {
                @{
                    'Local Address' = "$($conn.LocalAddress):$($conn.LocalPort)"
                    'Remote Address' = "$($conn.RemoteAddress):$($conn.RemotePort)"
                    'State' = $conn.State
                    'Process' = "$($conn.ProcessName) ($($conn.PID))"
                }
            }
        ) | ConvertTo-Json

        # Create HTML table
        $htmlTable = @"
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="table-dark">
                    <tr>
                        <th>Local Address</th>
                        <th>Remote Address</th>
                        <th>State</th>
                        <th>Process</th>
                    </tr>
                </thead>
                <tbody>
        "@

        foreach ($conn in $connections) {
            $htmlTable += @"
                    <tr>
                        <td>$($conn.LocalAddress):$($conn.LocalPort)</td>
                        <td>$($conn.RemoteAddress):$($conn.RemotePort)</td>
                        <td>$($conn.State)</td>
                        <td>$($conn.ProcessName) ($($conn.PID))</td>
                    </tr>
        "@
        }

        $htmlTable += @"
                </tbody>
            </table>
        </div>
        "@

        # Create text table
        $textTable = "Active Network Connections:`n"
        $textTable += "-" * 100 + "`n"
        $textTable += "Local Address                 Remote Address                State           Process`n"
        $textTable += "-" * 100 + "`n"

        foreach ($conn in $connections) {
            $local = "$($conn.LocalAddress):$($conn.LocalPort)".PadRight(30)
            $remote = "$($conn.RemoteAddress):$($conn.RemotePort)".PadRight(30)
            $state = $conn.State.PadRight(15)
            $process = "$($conn.ProcessName) ($($conn.PID))"

            $textTable += "$local $remote $state $process`n"
        }

        # Return both formats
        $result = @{
            Text = $textTable
            Html = $htmlTable
            Json = $connectionsJson
        } | ConvertTo-Json -Depth 3 -Compress

        Write-Output $result
        """

        result = run_powershell_command(command, timeout=60)  # Increase timeout as this can take longer

        try:
            # Try to parse the JSON result
            data = json.loads(result)

            # Return the appropriate format
            if hasattr(self, 'web_display') and self.web_display:
                return data['Html'].encode()
            else:
                return data['Text'].encode()
        except:
            # Fallback to simple format if JSON parsing fails
            fallback_script = """
            Get-NetTCPConnection |
            ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort = $_.RemotePort
                    State = $_.State
                    ProcessName = $process.ProcessName
                }
            } | Format-Table -AutoSize
            """
            try:
                result = subprocess.run(["powershell", "-Command", fallback_script],
                                    capture_output=True, text=True, check=True)

                connections_table = "Active Network Connections:\n"
                connections_table += "-" * 70 + "\n"
                connections_table += result.stdout
                return connections_table.encode()
            except subprocess.CalledProcessError as e:
                return f"Error retrieving connections: {str(e)}".encode()

    def rpc_service_check(self):
        table = "RPC Services:\n"
        table += "-" * 70 + "\n"
        table += f"{'Service Name':<30} {'Status':<10} {'PID'}\n"
        table += "-" * 70 + "\n"

        powershell_script = """
        Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -like "*rpc*" } |
        Select-Object Name, State, ProcessId | Format-Table -AutoSize
        """
        try:
            result = subprocess.run(["powershell", "-Command", powershell_script],
                                 capture_output=True, text=True, check=True)
            table += result.stdout
        except subprocess.CalledProcessError as e:
            table += f"Error: {str(e)}\n"
        return table.encode()

    def port_scanner(self, ip_to_scan):
        # Scan for open ports
        open_ports = []
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            8080: "HTTP Proxy"
        }

        # Scan common ports first
        for port in common_ports.keys():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip_to_scan, port))
                if result == 0:
                    service = common_ports.get(port, "Unknown")
                    open_ports.append({
                        'Port': port,
                        'Status': 'Open',
                        'Service': service
                    })
                sock.close()
            except Exception:
                continue

        # Scan other ports in range 1-1024
        for port in range(1, 1025):
            if port in common_ports:
                continue  # Skip already scanned common ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip_to_scan, port))
                if result == 0:
                    open_ports.append({
                        'Port': port,
                        'Status': 'Open',
                        'Service': 'Unknown'
                    })
                sock.close()
            except Exception:
                continue

        # Create HTML table
        html_output = f"""
        <div class="port-scan-results">
            <h4>Open Ports for {html.escape(ip_to_scan)}</h4>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="table-dark">
                        <tr>
                            <th>Port</th>
                            <th>Status</th>
                            <th>Service</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        if open_ports:
            for port_info in open_ports:
                html_output += f"""
                        <tr>
                            <td>{port_info['Port']}</td>
                            <td>{port_info['Status']}</td>
                            <td>{port_info['Service']}</td>
                        </tr>
                """
        else:
            html_output += """
                        <tr>
                            <td colspan="3">No open ports found</td>
                        </tr>
            """

        html_output += """
                    </tbody>
                </table>
            </div>
        </div>
        """

        # Create text table
        text_output = f"Open Ports for {ip_to_scan}:\n"
        text_output += "-" * 40 + "\n"
        text_output += "Port     Status    Service\n"
        text_output += "-" * 40 + "\n"

        if open_ports:
            for port_info in open_ports:
                text_output += f"{port_info['Port']:<8} {port_info['Status']:<9} {port_info['Service']}\n"
        else:
            text_output += "No open ports found\n"

        # Check if this is a web request
        if hasattr(self, 'web_display') and self.web_display:
            return html_output.encode()
        else:
            return text_output.encode()

    def banner_grabber(self, ip_to_scan):
        table = f"Service Banners for {ip_to_scan}:\n"
        table += "-" * 50 + "\n"
        table += f"{'Port':<8} {'Banner'}\n"
        table += "-" * 50 + "\n"

        for port in range(1, 1025):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((ip_to_scan, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    table += f"{port:<8} {banner}\n"
                sock.close()
            except:
                continue
        return table.encode()



def handle_os_info():
    table = "System Information:\n"
    table += "-" * 50 + "\n"
    table += f"System:     {platform.system()}\n"
    table += f"Node:       {platform.node()}\n"
    table += f"Release:    {platform.release()}\n"
    table += f"Version:    {platform.version()}\n"
    table += f"Machine:    {platform.machine()}\n"
    table += f"Processor:  {platform.processor()}\n"
    return table.encode()


def handle_installed_products():
     return b"Dummy products list"


def command_dispatcher(cmd_code, **kwargs):
    os_info = OsInfo()

    # Set web_display flag for better formatting in web UI
    os_info.web_display = True

    # Initialize NetworkInfo with custom network parameters if provided
    ip_to_scan = kwargs.get("ip", "192.168.29.1")
    network = kwargs.get("network", "192.168.29.0/24")
    net_info = NetworkInfo(routerip=ip_to_scan, network=network, web_display=True)

    # Parse section name for section-based commands
    section_name = None
    if cmd_code == CMD_GET_OS_INFO_SECTION and ":" in ip_to_scan:
        parts = ip_to_scan.split(":", 1)
        section_name = parts[0].strip()
        ip_to_scan = parts[1].strip() if len(parts) > 1 else "192.168.29.1"

    # Basic command codes
    if cmd_code == CMD_OS_INFO:
        return os_info.handle_basic_info()

    elif cmd_code == CMD_GET_POWERSHELL_HISTORY:
        return os_info.get_powershell_history()

    elif cmd_code == CMD_LIST_PRODUCTS:
        return os_info.get_installed_products()

    elif cmd_code == CMD_NETWORK_SCAN:
        return net_info.arp_scan()

    elif cmd_code == CMD_SYSTEM_DIAG:
        return os_info.get_os_info()

    # OS Info command codes
    elif cmd_code == CMD_GET_OS_INFO:
        return os_info.get_os_info()

    elif cmd_code == CMD_GET_AMSI_PROVIDERS:
        return os_info.get_amsi_providers()

    elif cmd_code == CMD_GET_REGISTERED_ANTIVIRUS:
        return os_info.get_registered_antivirus()

    elif cmd_code == CMD_GET_WINDOWS_DEFENDER_SETTINGS:
        return os_info.get_windows_defender_settings()

    elif cmd_code == CMD_GET_AUTO_RUN_EXECUTABLES:
        return os_info.get_auto_run_executables()

    elif cmd_code == CMD_GET_CERTIFICATES:
        return os_info.get_certificates()

    elif cmd_code == CMD_GET_ENVIRONMENT_VARIABLES:
        return os_info.get_environment_variables()

    elif cmd_code == CMD_LIST_USER_FOLDERS:
        return os_info.list_user_folders()

    elif cmd_code == CMD_GET_FILE_VERSION:
        file_path = kwargs.get("file_path", r"C:\Windows\System32\notepad.exe")
        return os_info.get_file_version(file_path)

    elif cmd_code == CMD_GET_INSTALLED_HOTFIXES:
        return os_info.get_installed_hotfixes()

    elif cmd_code == CMD_GET_INSTALLED_PRODUCTS:
        return os_info.get_installed_products()

    elif cmd_code == CMD_GET_NON_EMPTY_LOCAL_GROUPS:
        return os_info.get_non_empty_local_groups()

    elif cmd_code == CMD_GET_LOCAL_USERS:
        return os_info.get_local_users()

    elif cmd_code == CMD_GET_MS_UPDATES:
        return os_info.get_ms_updates()

    elif cmd_code == CMD_GET_NTLM_SETTINGS:
        return os_info.get_ntlm_settings()

    elif cmd_code == CMD_GET_RDP_CONNECTIONS:
        return os_info.get_rdp_connections()

    elif cmd_code == CMD_GET_SECURE_BOOT_INFO:
        return os_info.get_secure_boot_info()

    elif cmd_code == CMD_GET_SYSMON_CONFIG:
        return os_info.get_sysmon_config()

    elif cmd_code == CMD_GET_UAC_POLICIES:
        return os_info.get_uac_policies()

    elif cmd_code == CMD_GET_AUDIT_POLICY:
        return os_info.get_audit_policy()

    elif cmd_code == CMD_GET_FIREWALL_RULES:
        return os_info.get_firewall_rules()

    # Network Info command codes
    elif cmd_code == CMD_ARP_SCAN:
        return net_info.arp_scan()

    elif cmd_code == CMD_DNS_CACHE:
        return net_info.dns_cache()

    elif cmd_code == CMD_WINDOWS_NETWORK_PROFILE:
        return net_info.windows_network_profile()

    elif cmd_code == CMD_NETWORK_SHARES:
        return net_info.network_shares()

    elif cmd_code == CMD_TCP_UDP_CONNECTIONS:
        return net_info.tcp_udp_connections()

    elif cmd_code == CMD_RPC_SERVICE_CHECK:
        return net_info.rpc_service_check()

    elif cmd_code == CMD_PORT_SCANNER:
        return net_info.port_scanner(ip_to_scan)

    elif cmd_code == CMD_BANNER_GRABBER:
        return net_info.banner_grabber(ip_to_scan)

    # Section-based OS info
    elif cmd_code == CMD_GET_OS_INFO_SECTION:
        # Get a specific section of the OS info report
        if not section_name:
            return "Error: No section name provided. Format should be 'section_name:optional_param'".encode()

        print(f"[+] Requested OS info section: {section_name}")

        # Define all available sections with their functions
        section_map = {
            "system_overview": lambda: os_info.handle_basic_info(),
            "os_details": lambda: os_info.get_os_info(),
            "environment_variables": lambda: os_info.get_environment_variables(),
            "user_folders": lambda: os_info.list_user_folders(),
            "file_version": lambda: os_info.get_file_version(),
            "installed_software": lambda: os_info.get_installed_products(),
            "installed_hotfixes": lambda: os_info.get_installed_hotfixes(),
            "windows_updates": lambda: os_info.get_ms_updates(),
            "amsi_providers": lambda: os_info.get_amsi_providers(),
            "antivirus_info": lambda: os_info.get_registered_antivirus(),
            "defender_settings": lambda: os_info.get_windows_defender_settings(),
            "auto_run_executables": lambda: os_info.get_auto_run_executables(),
            "certificates": lambda: os_info.get_certificates(),
            "firewall_rules": lambda: os_info.get_firewall_rules(),
            "audit_policy": lambda: os_info.get_audit_policy(),
            "ntlm_settings": lambda: os_info.get_ntlm_settings(),
            "rdp_connections": lambda: os_info.get_rdp_connections(),
            "secure_boot_info": lambda: os_info.get_secure_boot_info(),
            "sysmon_config": lambda: os_info.get_sysmon_config(),
            "uac_policies": lambda: os_info.get_uac_policies(),
            "local_groups": lambda: os_info.get_non_empty_local_groups(),
            "local_users": lambda: os_info.get_local_users(),
            "powershell_history": lambda: os_info.get_powershell_history()
        }

        # Check if the requested section exists
        if section_name not in section_map:
            available_sections = ", ".join(section_map.keys())
            return f"Error: Unknown section '{section_name}'. Available sections: {available_sections}".encode()

        # Get the section data
        try:
            section_data = section_map[section_name]()

            # Check if the result is already HTML
            if isinstance(section_data, bytes):
                section_text = section_data.decode('utf-8', errors='ignore')
            else:
                section_text = section_data

            # If the content already starts with HTML tags, return it directly
            if section_text.strip().startswith(('<div', '<table', '<!DOCTYPE html>', '<html>')):
                return section_text.encode()

            # Create a professional HTML wrapper for the section
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Section: {section_name}</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Arial, sans-serif;
                        padding: 20px;
                        background-color: #f8f9fa;
                        margin: 0;
                    }}
                    .section-content {{
                        background-color: white;
                        border-radius: 8px;
                        padding: 20px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        max-width: 1200px;
                        margin: 0 auto;
                    }}
                    pre {{
                        background-color: #f8f9fa;
                        padding: 15px;
                        border-radius: 6px;
                        overflow-x: auto;
                        white-space: pre-wrap;
                        font-family: 'Consolas', 'Courier New', monospace;
                        font-size: 14px;
                        border: 1px solid #e9ecef;
                        line-height: 1.5;
                    }}
                    .section-header {{
                        background-color: #0d6efd;
                        color: white;
                        padding: 15px 20px;
                        font-weight: 600;
                        font-size: 20px;
                        margin: -20px -20px 20px -20px;
                        border-radius: 8px 8px 0 0;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-bottom: 1rem;
                    }}
                    th, td {{
                        padding: 0.75rem;
                        text-align: left;
                        border-bottom: 1px solid #dee2e6;
                    }}
                    th {{
                        background-color: #f8f9fa;
                        font-weight: 600;
                    }}
                    tr:nth-child(even) {{
                        background-color: #f8f9fa;
                    }}
                    tr:hover {{
                        background-color: #e9ecef;
                    }}
                </style>
            </head>
            <body>
                <div class="section-content">
                    <div class="section-header">
                        <span>{section_name.replace('_', ' ').title()}</span>
                        <span>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
                    </div>
                    <pre>{html.escape(section_text)}</pre>
                </div>
            </body>
            </html>
            """

            return html_content.encode()

        except Exception as e:
            error_msg = f"Error retrieving section '{section_name}': {str(e)}"
            print(f"[!] {error_msg}")
            return error_msg.encode()

    # Full reports
    elif cmd_code == CMD_FULL_OS_INFO:
        # For web dashboard, create an HTML-formatted version of the full OS info
        report_title = "System Information Report"

        # Define sections with functions to call
        # We'll wrap each function call in a try-except block to ensure one failure doesn't stop everything
        section_definitions = [
            # Basic System Information
            {
                "name": "System Overview",
                "function": lambda: os_info.handle_basic_info(),
                "formatter": format_system_info,
                "critical": False,
                "category": "System Information"
            },
            {
                "name": "Operating System Details",
                "function": lambda: os_info.get_os_info(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "System Information"
            },
            {
                "name": "Environment Variables",
                "function": lambda: os_info.get_environment_variables(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "System Information"
            },
            {
                "name": "User Folders",
                "function": lambda: os_info.list_user_folders(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "System Information"
            },
            {
                "name": "File Version Information",
                "function": lambda: os_info.get_file_version(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "System Information"
            },

            # Software & Updates
            {
                "name": "Installed Software",
                "function": lambda: os_info.get_installed_products(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Software & Updates"
            },
            {
                "name": "Installed Hotfixes",
                "function": lambda: os_info.get_installed_hotfixes(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Software & Updates"
            },
            {
                "name": "Windows Updates",
                "function": lambda: os_info.get_ms_updates(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Software & Updates"
            },

            # Security Information
            {
                "name": "AMSI Providers",
                "function": lambda: os_info.get_amsi_providers(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Antivirus Information",
                "function": lambda: os_info.get_registered_antivirus(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Windows Defender Status",
                "function": lambda: os_info.get_windows_defender_settings(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Auto Run Executables",
                "function": lambda: os_info.get_auto_run_executables(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Certificates",
                "function": lambda: os_info.get_certificates(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Firewall Rules",
                "function": lambda: os_info.get_firewall_rules(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Audit Policy",
                "function": lambda: os_info.get_audit_policy(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "NTLM Settings",
                "function": lambda: os_info.get_ntlm_settings(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "RDP Connections",
                "function": lambda: os_info.get_rdp_connections(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Secure Boot Information",
                "function": lambda: os_info.get_secure_boot_info(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "Sysmon Configuration",
                "function": lambda: os_info.get_sysmon_config(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },
            {
                "name": "UAC Policies",
                "function": lambda: os_info.get_uac_policies(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Security Information"
            },

            # User Information
            {
                "name": "Local Groups",
                "function": lambda: os_info.get_non_empty_local_groups(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "User Information"
            },
            {
                "name": "User Accounts",
                "function": lambda: os_info.get_local_users(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "User Information"
            },
            {
                "name": "PowerShell History",
                "function": lambda: os_info.get_powershell_history(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "User Information"
            }
        ]

        print("[+] Starting HTML OS Information collection...")
        success_count = 0
        failure_count = 0
        html_sections = []

        for section in section_definitions:
            section_name = section["name"]
            section_func = section["function"]
            formatter = section.get("formatter", text_to_html_table)
            is_critical = section["critical"]

            try:
                print(f"  [*] Collecting {section_name}...", end='', flush=True)

                try:
                    # Call the function and get the data
                    section_data = section_func()

                    # Decode the data if needed
                    decoded_data = section_data.decode() if isinstance(section_data, bytes) else section_data

                    if decoded_data and decoded_data.strip():
                        # Format the data as HTML
                        html_content = formatter(decoded_data)
                        html_sections.append({
                            "title": section_name,
                            "content": html_content,
                            "status": "success",
                            "category": section.get("category", "General")
                        })
                        success_count += 1
                    else:
                        html_sections.append({
                            "title": section_name,
                            "content": "<p>No data available</p>",
                            "status": "error" if is_critical else "success",
                            "category": section.get("category", "General")
                        })
                        if is_critical:
                            failure_count += 1

                    print(" Done")
                except Exception as decode_error:
                    error_msg = f"Error processing data: {str(decode_error)}"
                    html_sections.append({
                        "title": section_name,
                        "content": format_error_message(error_msg),
                        "status": "error",
                        "category": section.get("category", "General")
                    })
                    print(f" Error: {error_msg}")
                    if is_critical:
                        failure_count += 1

            except Exception as section_error:
                error_msg = f"Error collecting {section_name}: {str(section_error)}"
                print(f" Failed: {error_msg}")
                html_sections.append({
                    "title": section_name,
                    "content": format_error_message(error_msg),
                    "status": "error",
                    "category": section.get("category", "General")
                })
                if is_critical:
                    failure_count += 1

        # Add summary section
        html_sections.append({
            "summary": True,
            "success_count": success_count,
            "failure_count": failure_count
        })

        print(f"[+] OS Information collection completed: {success_count} successful, {failure_count} critical failures")

        # Generate the final HTML report
        html_report = format_html_output(report_title, html_sections)
        return html_report.encode()

    elif cmd_code == CMD_FULL_NETWORK_INFO:
        # For web dashboard, create an HTML-formatted version of the network info
        report_title = "Network Information Report"

        # Define sections with functions to call
        section_definitions = [
            {
                "name": "Network Devices",
                "function": lambda: net_info.arp_scan(),
                "formatter": text_to_html_table,
                "critical": True,  # This is important for network info
                "category": "Network Discovery"
            },
            {
                "name": "Network Shares",
                "function": lambda: net_info.network_shares(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Network Resources"
            },
            {
                "name": "Active Connections",
                "function": lambda: net_info.tcp_udp_connections(),
                "formatter": text_to_html_table,
                "critical": False,
                "category": "Network Activity"
            },
            {
                "name": "Open Ports",
                "function": lambda: net_info.port_scanner(ip_to_scan),
                "formatter": text_to_html_table,
                "critical": True,
                "category": "Network Security"
            }
        ]

        print("[+] Starting HTML Network Information collection...")
        success_count = 0
        failure_count = 0
        html_sections = []

        for section in section_definitions:
            section_name = section["name"]
            section_func = section["function"]
            formatter = section.get("formatter", text_to_html_table)
            is_critical = section["critical"]

            try:
                print(f"  [*] Collecting {section_name}...", end='', flush=True)

                try:
                    # Call the function and get the data
                    section_data = section_func()

                    # Decode the data if needed
                    decoded_data = section_data.decode() if isinstance(section_data, bytes) else section_data

                    if decoded_data and decoded_data.strip():
                        # Format the data as HTML
                        html_content = formatter(decoded_data)
                        html_sections.append({
                            "title": section_name,
                            "content": html_content,
                            "status": "success",
                            "category": section.get("category", "General")
                        })
                        success_count += 1
                    else:
                        html_sections.append({
                            "title": section_name,
                            "content": "<p>No data available</p>",
                            "status": "error" if is_critical else "success",
                            "category": section.get("category", "General")
                        })
                        if is_critical:
                            failure_count += 1

                    print(" Done")
                except Exception as decode_error:
                    error_msg = f"Error processing data: {str(decode_error)}"
                    html_sections.append({
                        "title": section_name,
                        "content": format_error_message(error_msg),
                        "status": "error",
                        "category": section.get("category", "General")
                    })
                    print(f" Error: {error_msg}")
                    if is_critical:
                        failure_count += 1

            except Exception as section_error:
                error_msg = f"Error collecting {section_name}: {str(section_error)}"
                print(f" Failed: {error_msg}")
                html_sections.append({
                    "title": section_name,
                    "content": format_error_message(error_msg),
                    "status": "error",
                    "category": section.get("category", "General")
                })
                if is_critical:
                    failure_count += 1

        # Add summary section
        html_sections.append({
            "summary": True,
            "success_count": success_count,
            "failure_count": failure_count
        })

        print(f"[+] Network Information collection completed: {success_count} successful, {failure_count} critical failures")

        # Generate the final HTML report
        html_report = format_html_output(report_title, html_sections)
        return html_report.encode()

    else:
        return f"Unknown command code: {cmd_code}".encode()
