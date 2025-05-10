"""
URL patterns for the port scanner functionality.
"""

from django.urls import path
from . import views_port_scanner, views_port_vuln_scanner

urlpatterns = [
    # Port scanner main page
    path('port-scanner/', views_port_scanner.port_scanner_home, name='port_scanner_home'),

    # Start a new port scan
    path('port-scanner/start/', views_port_scanner.start_port_scan, name='start_port_scan'),

    # Stop a running port scan
    path('port-scanner/stop/<int:target_id>/', views_port_scanner.stop_port_scan, name='stop_port_scan'),

    # Get scan status
    path('port-scanner/status/<int:target_id>/', views_port_scanner.scan_status, name='scan_status'),

    # View scan results
    path('port-scanner/results/<int:scan_id>/', views_port_scanner.port_scanner_results, name='port_scanner_results'),

    # AJAX scan results
    path('port-scanner/results/<int:scan_id>/ajax/', views_port_scanner.port_scanner_results_ajax, name='port_scanner_results_ajax'),

    # View scan history
    path('port-scanner/history/', views_port_scanner.port_scanner_history, name='port_scanner_history'),

    # View port details
    path('port-scanner/port/<int:port_id>/', views_port_scanner.port_details, name='port_details'),

    # Export scan results
    path('port-scanner/export/<int:scan_id>/', views_port_scanner.export_scan_results, name='export_scan_results'),

    # Delete scan result
    path('port-scanner/delete/<int:scan_id>/', views_port_scanner.delete_scan_result, name='delete_scan_result'),

    # Check nmap availability
    path('port-scanner/check-nmap/', views_port_scanner.check_nmap_availability, name='check_nmap_availability'),

    # Update scan notes
    path('port-scanner/update-notes/', views_port_scanner.update_scan_notes, name='update_scan_notes'),

    # Vanish port scanner data
    path('port-scanner/vanish/', views_port_scanner.vanish_port_scanner_data, name='vanish_port_scanner_data'),

    # Port vulnerability scanner
    path('port-scanner/vuln-scan/<int:scan_id>/start/', views_port_vuln_scanner.start_port_vuln_scan, name='start_port_vuln_scan'),
    path('port-scanner/vuln-scan/status/', views_port_vuln_scanner.port_vuln_scan_status, name='port_vuln_scan_status'),
    path('port-scanner/vuln-scan/<int:scan_id>/stop/', views_port_vuln_scanner.stop_port_vuln_scan, name='stop_port_vuln_scan'),
    path('port-scanner/vuln-scan/<int:scan_id>/results/', views_port_vuln_scanner.port_vuln_scan_results, name='port_vuln_scan_results'),
]
