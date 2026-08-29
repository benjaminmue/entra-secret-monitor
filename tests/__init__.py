"""
Test package for the Entra Secret Monitor.

The application modules live in app/ and import each other flat ("import
graph"), the way they do inside the container. Putting that directory on the
path here keeps every test module free of its own path juggling.
"""
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
