"""
portal

Web portal (v2) of the Entra ID credential monitor.

Adds persistence, authentication with TOTP, customer management and a
distributed daily scan schedule on top of the stateless service in app/.
The Graph logic itself is reused unchanged from app/graph.py.
"""

from portal.factory import create_app

__all__ = ["create_app"]
