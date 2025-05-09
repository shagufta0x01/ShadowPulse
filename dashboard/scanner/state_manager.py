"""
State Manager for Background Processes

This module provides functionality to manage the state of background processes
across page navigations and browser sessions.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from django.utils import timezone

# Configure logging
logger = logging.getLogger(__name__)

# Dictionary to store active processes
# Format: {process_id: {type: str, start_time: datetime, data: dict, thread: Thread}}
active_processes = {}

# Lock for thread-safe operations on the active_processes dictionary
process_lock = threading.Lock()

def register_process(process_id, data=None, process_type=None):
    """
    Register a new background process.

    Args:
        process_id (str): Unique identifier for the process
        data (dict): Data to store with the process
        process_type (str, optional): Type of process (e.g., 'port_scan', 'vulnerability_scan')

    Returns:
        bool: True if registration was successful, False otherwise
    """
    with process_lock:
        if process_id in active_processes:
            logger.warning(f"Process {process_id} already registered")
            return False

        # If data is a dict and contains a 'type' key, use that as process_type
        if isinstance(data, dict) and 'type' in data and process_type is None:
            process_type = data.pop('type')

        # If process_type is still None, extract it from process_id
        if process_type is None:
            parts = process_id.split('_')
            if len(parts) > 0:
                process_type = parts[0]
            else:
                process_type = 'unknown'

        active_processes[process_id] = {
            'type': process_type,
            'start_time': timezone.now(),
            'data': data or {},
            'thread': None
        }

        logger.info(f"Registered process {process_id} of type {process_type}")
        return True

def register_thread(process_id, thread):
    """
    Register a thread with an existing process.

    Args:
        process_id (str): Process identifier
        thread (Thread): Thread object to register

    Returns:
        bool: True if registration was successful, False otherwise
    """
    with process_lock:
        if process_id not in active_processes:
            logger.warning(f"Cannot register thread: Process {process_id} not found")
            return False

        active_processes[process_id]['thread'] = thread
        logger.info(f"Registered thread for process {process_id}")
        return True

def unregister_process(process_id):
    """
    Unregister a background process.

    Args:
        process_id (str): Process identifier

    Returns:
        bool: True if unregistration was successful, False otherwise
    """
    with process_lock:
        if process_id not in active_processes:
            logger.warning(f"Process {process_id} not found for unregistration")
            return False

        # Check if thread is still running
        thread = active_processes[process_id].get('thread')
        if thread and thread.is_alive():
            logger.warning(f"Process {process_id} still has a running thread")
            return False

        del active_processes[process_id]
        logger.info(f"Unregistered process {process_id}")
        return True

def get_process(process_id):
    """
    Get information about a registered process.

    Args:
        process_id (str): Process identifier

    Returns:
        dict: Process information or None if not found
    """
    with process_lock:
        if process_id not in active_processes:
            return None

        # Create a copy of the process info without the thread
        process_info = active_processes[process_id].copy()
        if 'thread' in process_info:
            thread = process_info['thread']
            process_info['thread_alive'] = thread.is_alive() if thread else False
            del process_info['thread']  # Don't include thread object in the returned data

        return process_info

def get_all_processes():
    """
    Get information about all registered processes.

    Returns:
        dict: Dictionary of process information
    """
    with process_lock:
        result = {}
        for process_id, process_info in active_processes.items():
            # Create a copy of the process info without the thread
            process_copy = process_info.copy()
            if 'thread' in process_copy:
                thread = process_copy['thread']
                process_copy['thread_alive'] = thread.is_alive() if thread else False
                del process_copy['thread']

            result[process_id] = process_copy

        return result

def update_process_data(process_id, data):
    """
    Update the data associated with a process.

    Args:
        process_id (str): Process identifier
        data (dict): New data to merge with existing data

    Returns:
        bool: True if update was successful, False otherwise
    """
    with process_lock:
        if process_id not in active_processes:
            logger.warning(f"Process {process_id} not found for data update")
            return False

        # Merge new data with existing data
        active_processes[process_id]['data'].update(data)
        logger.debug(f"Updated data for process {process_id}")
        return True

def is_process_running(process_id):
    """
    Check if a process is registered and its thread is running.

    Args:
        process_id (str): Process identifier

    Returns:
        bool: True if the process is running, False otherwise
    """
    with process_lock:
        if process_id not in active_processes:
            return False

        thread = active_processes[process_id].get('thread')
        return thread is not None and thread.is_alive()

def cleanup_stale_processes(max_age_hours=24):
    """
    Clean up processes that have been running for too long.

    Args:
        max_age_hours (int): Maximum age in hours for a process

    Returns:
        int: Number of processes cleaned up
    """
    with process_lock:
        now = timezone.now()
        max_age = timedelta(hours=max_age_hours)
        stale_processes = []

        for process_id, process_info in active_processes.items():
            start_time = process_info.get('start_time')
            if start_time and (now - start_time) > max_age:
                stale_processes.append(process_id)

        for process_id in stale_processes:
            thread = active_processes[process_id].get('thread')
            if thread and thread.is_alive():
                logger.warning(f"Stale process {process_id} still has a running thread")
                # We don't forcibly terminate threads as it's not safe

            del active_processes[process_id]
            logger.info(f"Cleaned up stale process {process_id}")

        return len(stale_processes)

def serialize_process_for_session(process_id):
    """
    Serialize process information for storage in a session.

    Args:
        process_id (str): Process identifier

    Returns:
        dict: Serialized process information or None if not found
    """
    process_info = get_process(process_id)
    if not process_info:
        return None

    # Convert datetime to string for JSON serialization
    if 'start_time' in process_info and isinstance(process_info['start_time'], datetime):
        process_info['start_time'] = process_info['start_time'].isoformat()

    return process_info

def restore_process_from_session(process_id, session_data):
    """
    Restore a process from session data.

    Args:
        process_id (str): Process identifier
        session_data (dict): Serialized process information

    Returns:
        bool: True if restoration was successful, False otherwise
    """
    if not session_data:
        return False

    # Convert string back to datetime
    if 'start_time' in session_data and isinstance(session_data['start_time'], str):
        try:
            session_data['start_time'] = datetime.fromisoformat(session_data['start_time'])
        except ValueError:
            session_data['start_time'] = timezone.now()

    with process_lock:
        active_processes[process_id] = {
            'type': session_data.get('type', 'unknown'),
            'start_time': session_data.get('start_time', timezone.now()),
            'data': session_data.get('data', {}),
            'thread': None  # Threads cannot be restored from session
        }

    logger.info(f"Restored process {process_id} from session")
    return True

def delayed_unregister(process_id, delay_seconds=60):
    """
    Unregister a process after a delay.

    Args:
        process_id (str): Process identifier
        delay_seconds (int): Delay in seconds before unregistering

    Returns:
        bool: True if the delayed unregistration was scheduled, False otherwise
    """
    if process_id not in active_processes:
        logger.warning(f"Process {process_id} not found for delayed unregistration")
        return False

    def _delayed_unregister_task():
        time.sleep(delay_seconds)
        unregister_process(process_id)

    thread = threading.Thread(target=_delayed_unregister_task)
    thread.daemon = True
    thread.start()

    logger.info(f"Scheduled delayed unregistration for process {process_id} in {delay_seconds} seconds")
    return True

def is_thread_alive(process_id):
    """
    Check if the thread associated with a process is alive.

    Args:
        process_id (str): Process identifier

    Returns:
        bool: True if the thread is alive, False otherwise
    """
    with process_lock:
        if process_id not in active_processes:
            return False

        thread = active_processes[process_id].get('thread')
        return thread is not None and thread.is_alive()

def get_process_data(process_id):
    """
    Get the data associated with a process.

    Args:
        process_id (str): Process identifier

    Returns:
        dict: Process data or None if not found
    """
    with process_lock:
        if process_id not in active_processes:
            return None

        return active_processes[process_id].get('data', {})
