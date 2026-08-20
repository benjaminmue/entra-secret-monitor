#!/usr/bin/env python3
"""Container health probe: succeeds when /healthz answers with HTTP 200."""

import os
import sys
import urllib.request

URL = "http://127.0.0.1:%s/healthz" % os.environ.get("LISTEN_PORT", "8099")

try:
    with urllib.request.urlopen(URL, timeout=4) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:                                         # noqa: BLE001
    sys.exit(1)
