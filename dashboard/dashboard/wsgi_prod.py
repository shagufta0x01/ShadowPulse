"""
WSGI config for dashboard project in production.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dashboard.settings_prod')

application = get_wsgi_application()
