"""
Render / gunicorn friendly entrypoint.

Render typically looks for an `app` object in `app.py` (or a gunicorn command that
imports it). Keeping this file at repo root avoids "Not Found" surprises when
the real Flask app lives in a subfolder.
"""

from firewall_final.app import app  # noqa: F401

