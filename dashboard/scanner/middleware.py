"""
Middleware for handling background process state.
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from . import state_manager

# Configure logging
logger = logging.getLogger(__name__)

class ProcessStateMiddleware(MiddlewareMixin):
    """
    Middleware to synchronize process state between the session and the state manager.
    """

    def process_request(self, request):
        """
        Process the request before the view is called.

        This method restores process state from the session if needed.
        """
        if not hasattr(request, 'session'):
            return None

        # Check if there are active processes in the session
        active_processes = request.session.get('active_processes', {})

        for process_id, process_info in active_processes.items():
            process_type = process_info.get('type')

            if not process_id or not process_type:
                continue

            # Check if the process is already registered
            if state_manager.get_process(process_id) is None:
                # Restore the process from session data
                state_manager.restore_process_from_session(process_id, process_info)
                logger.debug(f"Restored process {process_id} from session")

        # For backward compatibility - handle old active_scans format
        active_scans = request.session.get('active_scans', {})

        for target_id, scan_info in active_scans.items():
            scan_id = scan_info.get('scan_id')
            scan_type = scan_info.get('scan_type')

            if not scan_id or not scan_type:
                continue

            # Create a process ID
            process_id = f"{scan_type}_{scan_id}"

            # Check if the process is already registered
            if state_manager.get_process(process_id) is None:
                # Restore the process from session data
                state_manager.restore_process_from_session(process_id, {
                    'type': scan_type,
                    'start_time': scan_info.get('start_time'),
                    'data': {
                        'scan_id': scan_id,
                        'target_id': target_id,
                    }
                })

                logger.debug(f"Restored process {process_id} from session (legacy format)")

        return None

    def process_response(self, request, response):
        """
        Process the response after the view is called.

        This method updates the session with the current process state.
        """
        if not hasattr(request, 'session'):
            return response

        # Get all active processes
        all_processes = state_manager.get_all_processes()

        # Initialize active_processes in session if it doesn't exist
        if 'active_processes' not in request.session:
            request.session['active_processes'] = {}

        # Update session with active processes
        for process_id, process_info in all_processes.items():
            # Serialize process info for session storage
            serialized_info = state_manager.serialize_process_for_session(process_id)
            if serialized_info:
                # Update session
                request.session['active_processes'][process_id] = serialized_info
                request.session.modified = True

        # Clean up completed processes from session
        active_processes = request.session.get('active_processes', {})
        for process_id in list(active_processes.keys()):
            # Check if the process is still registered and running
            if not state_manager.is_process_running(process_id):
                # Remove from session
                del active_processes[process_id]
                request.session.modified = True

        # For backward compatibility - maintain the active_scans format
        if 'active_scans' not in request.session:
            request.session['active_scans'] = {}

        # Update active_scans from active processes
        active_scans = request.session.get('active_scans', {})

        # First, clear out any scans that are no longer active
        for target_id in list(active_scans.keys()):
            scan_info = active_scans[target_id]
            scan_id = scan_info.get('scan_id')
            scan_type = scan_info.get('scan_type')

            if not scan_id or not scan_type:
                continue

            # Create a process ID
            process_id = f"{scan_type}_{scan_id}"

            # Check if the process is still running
            if not state_manager.is_process_running(process_id):
                # Remove from session
                del active_scans[target_id]
                request.session.modified = True

        # Then, add any new scans from active processes
        for process_id, process_info in all_processes.items():
            if process_info.get('type') in ['port_scan', 'vulnerability_scan']:
                # Extract scan ID and target ID from process data
                scan_id = process_info.get('data', {}).get('scan_id')
                target_id = process_info.get('data', {}).get('target_id')

                if scan_id and target_id:
                    # Update session
                    request.session['active_scans'][target_id] = {
                        'scan_id': scan_id,
                        'scan_type': process_info.get('type'),
                        'start_time': process_info.get('start_time').isoformat() if hasattr(process_info.get('start_time'), 'isoformat') else None
                    }

                    # Mark session as modified
                    request.session.modified = True

        return response
