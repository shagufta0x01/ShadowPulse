from django.urls import path, include
from . import views
from . import views_monitoring
from . import urls_port_scanner
from . import views_software_vuln_scanner

app_name = 'scanner'

urlpatterns = [
    # Main pages
    path('', views.index, name='index'),
    path('os-info/', views.os_info, name='os_info'),
    path('os-info/installed-software/<int:target_id>/export-csv/', views.export_os_info_installed_software_csv, name='export_os_info_installed_software_csv'),
    path('network-info/', views.network_info, name='network_info'),
    path('processes/', views.processes, name='processes'),
    path('processes/data/', views.get_processes_data, name='get_processes_data'),
    path('processes/analyze/', views.analyze_process, name='analyze_process'),

    # Target management
    path('target/add/', views.add_target, name='add_target'),
    path('target/<int:target_id>/', views.target_detail, name='target_detail'),
    path('target/<int:target_id>/delete/', views.delete_target, name='delete_target'),

    # Command execution
    path('target/<int:target_id>/command/<int:command_code>/', views.send_command, name='send_command'),
    path('target/<int:target_id>/section/<str:section_id>/', views.get_os_info_section, name='get_os_info_section'),
    path('result/<int:result_id>/', views.get_scan_result, name='get_scan_result'),

    # Network scanning
    path('scan-network/', views.scan_network, name='scan_network'),
    path('clear-network-devices/', views.clear_network_devices, name='clear_network_devices'),

    # Help and support
    path('help-support/', views.help_support, name='help_support'),

    # Network Monitoring
    path('network-monitor/', views_monitoring.network_monitor_dashboard, name='network_monitor_dashboard'),
    path('network-monitor/start/', views_monitoring.start_network_monitor, name='start_network_monitor'),
    path('network-monitor/stop/', views_monitoring.stop_network_monitor, name='stop_network_monitor'),
    path('network-monitor/stats/', views_monitoring.network_monitor_stats, name='network_monitor_stats'),
    path('network-monitor/vanish/', views_monitoring.vanish_network_monitor_data, name='vanish_network_monitor_data'),
    path('network-alerts/', views_monitoring.network_alerts, name='network_alerts'),
    path('network-alerts/<int:alert_id>/resolve/', views_monitoring.resolve_alert, name='resolve_alert'),
    path('network-alerts/vanish/', views_monitoring.vanish_network_alerts_data, name='vanish_network_alerts_data'),

    # Vulnerability Management
    path('vulnerabilities/', views_monitoring.vulnerability_dashboard, name='vulnerability_dashboard'),
    path('vulnerabilities/start-scan/', views_monitoring.start_vulnerability_scan, name='start_vulnerability_scan'),
    path('vulnerabilities/stop-scan/', views_monitoring.stop_vulnerability_scan, name='stop_vulnerability_scan'),
    path('vulnerabilities/scan-status/<int:target_id>/', views_monitoring.vulnerability_scan_status, name='vulnerability_scan_status'),
    path('vulnerabilities/checkup/<int:checkup_id>/', views_monitoring.vulnerability_checkup_detail, name='vulnerability_checkup_detail'),
    path('vulnerabilities/list/', views_monitoring.vulnerabilities_list, name='vulnerabilities_list'),
    path('vulnerabilities/<int:vuln_id>/update-status/', views_monitoring.update_vulnerability_status, name='update_vulnerability_status'),
    path('vulnerabilities/vanish/', views_monitoring.vanish_vulnerability_data, name='vanish_vulnerability_data'),

    # Port Scanner
    path('', include(urls_port_scanner.urlpatterns)),

    # Software Vulnerability Scanner
    path('software-vulnerabilities/', views_software_vuln_scanner.software_vuln_scan_home, name='software_vuln_scan_home'),
    path('software-vulnerabilities/start/<int:target_id>/', views_software_vuln_scanner.start_software_vuln_scan, name='start_software_vuln_scan'),
    path('software-vulnerabilities/status/', views_software_vuln_scanner.software_vuln_scan_status, name='software_vuln_scan_status'),
    path('software-vulnerabilities/stop/<int:scan_id>/', views_software_vuln_scanner.stop_software_vuln_scan, name='stop_software_vuln_scan'),
    path('software-vulnerabilities/results/<int:scan_id>/', views_software_vuln_scanner.software_vuln_scan_results, name='software_vuln_scan_results'),
    path('software-vulnerabilities/vanish/', views_software_vuln_scanner.vanish_software_vuln_data, name='vanish_software_vuln_data'),
    path('software-vulnerabilities/detail/<int:vuln_id>/', views_software_vuln_scanner.software_vulnerability_detail, name='software_vulnerability_detail'),
    path('software-vulnerabilities/software/<int:target_id>/', views_software_vuln_scanner.installed_software_list, name='installed_software_list'),
    path('software-vulnerabilities/software/<int:target_id>/export-csv/', views_software_vuln_scanner.export_installed_software_csv, name='export_installed_software_csv'),

    # Add the URL pattern that matches the hardcoded URLs in the templates
    path('installed-software/<int:target_id>/', views_software_vuln_scanner.installed_software_list, name='installed_software_list_alt'),
    path('installed-software/<int:target_id>/export-csv/', views_software_vuln_scanner.export_installed_software_csv, name='export_installed_software_csv_alt'),
]
