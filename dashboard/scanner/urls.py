from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    # Main pages
    path('', views.index, name='index'),
    path('os-info/', views.os_info, name='os_info'),
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
]
