#!/usr/bin/env python3
"""
helpers.py

Small shared helpers for the view layer: role guards, config access and the
flash message wording used across the blueprints.
"""

from functools import wraps

from flask import abort, current_app, flash, redirect, url_for
from flask_login import current_user

from portal.models import ROLE_ADMIN, ROLE_OPERATOR


def config():
    """Return the PortalConfig of the running application."""
    return current_app.config["PORTAL"]


def require_role(*roles):
    """Decorator that rejects a signed in user without one of the given roles."""
    def decorator(view):
        """Wrap one view function."""
        @wraps(view)
        def wrapper(*args, **kwargs):
            """Check the role before delegating to the view."""
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def require_write(view):
    """Shortcut for the two roles that may change data."""
    return require_role(ROLE_ADMIN, ROLE_OPERATOR)(view)


def form_errors(form):
    """Flash every validation error of a form in a readable form."""
    for field_name, errors in form.errors.items():
        label = getattr(getattr(form, field_name, None), "label", None)
        title = label.text if label else field_name
        for error in errors:
            flash("%s: %s" % (title, error), "error")
