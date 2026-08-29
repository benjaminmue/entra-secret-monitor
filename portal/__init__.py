"""
portal

Web portal (v2) of the Entra ID credential monitor.

Adds persistence, authentication with TOTP, customer management and a
distributed daily scan schedule on top of the stateless service in app/.
The Graph logic itself is reused unchanged from app/graph.py.
"""

import os
import sys

# app/ holds the Graph logic that both the classic service and the portal use.
# Set here rather than in factory.py so every portal module can rely on it,
# including config.py, which is imported before the application is built.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "app"))

from portal.factory import create_app                                   # noqa: E402

__all__ = ["create_app"]
