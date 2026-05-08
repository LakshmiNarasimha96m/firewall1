"""
WSGI entrypoint for gunicorn: `gunicorn wsgi:app`
"""

from firewall_final.app import app  # noqa: F401

