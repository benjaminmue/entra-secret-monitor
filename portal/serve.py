#!/usr/bin/env python3
"""
serve.py

Entry point of the portal.

Runs the application on waitress, a pure Python WSGI server that works on
Linux and Windows alike. The Flask development server is deliberately not
used, it is single threaded and not meant to face a network.
"""

import sys

from portal.config import ConfigError, load_config
from portal.factory import create_app


def main():
    """Start the portal and serve until terminated."""
    try:
        cfg = load_config()
    except ConfigError as exc:
        print("Konfigurationsfehler:\n%s" % exc, file=sys.stderr)
        return 2

    try:
        from waitress import serve
    except ImportError:
        print("waitress fehlt. Der Flask-Entwicklungsserver ist kein Ersatz, er ist "
              "einzeln getaktet und nicht für ein Netz gedacht. "
              "Installation: pip install -r requirements-portal.txt", file=sys.stderr)
        return 3

    app = create_app(cfg)

    print("Portal läuft auf %s:%d" % (cfg.listen_addr, cfg.listen_port), flush=True)
    serve(app, host=cfg.listen_addr, port=cfg.listen_port, threads=8,
          ident="EntraCredentialPortal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
