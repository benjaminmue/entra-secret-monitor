#!/usr/bin/env python3
"""
factory.py

Application factory: wires configuration, database, login, CSRF protection,
security headers, blueprints and the scan scheduler into a Flask app.
"""

import os
import sys
from datetime import timedelta

from flask import Flask, g, render_template, request
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect

from portal import audit, scheduler                                    # noqa: E402
from portal.config import load_config                                  # noqa: E402
from portal.db import Session, create_all, init_engine, remove_session  # noqa: E402
from portal.models import ROLE_ADMIN, ROLE_OPERATOR, SchemaInfo, User  # noqa: E402
from portal.security import hash_password                              # noqa: E402

csrf = CSRFProtect()
login_manager = LoginManager()

# Everything the pages need comes from this origin. No inline script, no CDN,
# so an injected string can never execute even if a template escape were missed.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def create_app(config=None):
    """Build and return the configured Flask application."""
    cfg = config or load_config()
    for warning in cfg.warnings:
        print("WARNUNG: %s" % warning, flush=True)

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=cfg.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg.cookie_secure,
        SESSION_COOKIE_NAME="portal_session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=cfg.session_minutes),
        MAX_CONTENT_LENGTH=1024 * 1024,
        WTF_CSRF_TIME_LIMIT=cfg.session_minutes * 60,
        PORTAL=cfg,
    )

    init_engine(cfg.database_url)
    create_all()
    _ensure_schema_row()
    _bootstrap_admin(cfg)

    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Bitte zuerst anmelden."
    login_manager.session_protection = "strong"

    _register_blueprints(app)
    _register_hooks(app, cfg)

    if cfg.scheduler_enabled:
        scheduler.start(cfg)
    return app


@login_manager.user_loader
def _load_user(user_id):
    """Resolve the session user id to a User row, ignoring disabled accounts."""
    try:
        user = Session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    return user if user and user.is_active else None


def _register_blueprints(app):
    """Attach every route group and exempt the PRTG endpoint from CSRF."""
    from portal.views import auth, customers, dashboard, docs, prtg, users

    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(customers.bp)
    app.register_blueprint(users.bp)
    app.register_blueprint(docs.bp)
    app.register_blueprint(prtg.bp)
    csrf.exempt(prtg.bp)


def _register_hooks(app, cfg):
    """Register teardown, security headers, template globals and error pages."""
    app.teardown_appcontext(remove_session)

    @app.before_request
    def _harden_session():
        """Keep the session short lived and expose the config to the request."""
        from flask import session
        session.permanent = True
        g.portal = cfg

    @app.after_request
    def _security_headers(response):
        """Send the headers a browser needs to protect the portal."""
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy",
                                    "geolocation=(), camera=(), microphone=()")
        if cfg.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains")
        if request.path.startswith(("/prtg", "/json", "/api")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def _template_globals():
        """Values every template needs without passing them through each view."""
        return {
            "instance_name": cfg.instance_name,
            "is_admin": current_user.is_authenticated and current_user.role == ROLE_ADMIN,
            "may_write": current_user.is_authenticated
                         and current_user.role in (ROLE_ADMIN, ROLE_OPERATOR),
        }

    @app.errorhandler(403)
    def _forbidden(_error):
        """Render the styled error page instead of the Flask default."""
        return render_template("error.html", code=403,
                               message="Für diese Aktion fehlt die Berechtigung."), 403

    @app.errorhandler(404)
    def _not_found(_error):
        """Render the styled error page instead of the Flask default."""
        return render_template("error.html", code=404,
                               message="Seite nicht gefunden."), 404

    @app.errorhandler(500)
    def _server_error(error):
        """Log the exception and show a neutral page without a stack trace."""
        print("500: %s" % error, flush=True)
        return render_template("error.html", code=500,
                               message="Unerwarteter Fehler. Details stehen im Log."), 500


def _ensure_schema_row():
    """Write the schema marker on a fresh database."""
    from portal.db import session_scope
    with session_scope() as session:
        if session.query(SchemaInfo).count() == 0:
            session.add(SchemaInfo(version=1))


def _bootstrap_admin(cfg):
    """
    Create the first administrator from the environment when no user exists.

    Runs only on an empty user table. The account starts with
    must_change_password set and without a second factor, both of which the
    login flow forces before anything else becomes reachable.
    """
    from portal.db import session_scope
    with session_scope() as session:
        if session.query(User).count() > 0:
            return
        username = cfg.bootstrap_user or "admin"
        password = cfg.bootstrap_password
        if not password:
            print("Kein PORTAL_BOOTSTRAP_PASSWORD gesetzt, kein Startkonto angelegt. "
                  "Container mit gesetzter Variable einmal neu starten.", flush=True)
            return
        session.add(User(
            username=username,
            display_name="Erstkonto",
            role=ROLE_ADMIN,
            password_hash=hash_password(password),
            must_change_password=True,
            created_by="bootstrap",
        ))
        audit.log(session, "user.bootstrap", actor="system", target=username,
                  detail="Erstkonto aus PORTAL_BOOTSTRAP_USER angelegt", commit=False)
        print("Erstkonto '%s' angelegt, Passwortwechsel und 2FA beim ersten Login erzwungen."
              % username, flush=True)
