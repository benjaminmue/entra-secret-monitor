#!/usr/bin/env python3
"""
db.py

SQLAlchemy plumbing: engine, scoped session and schema creation.

Every database access in the portal goes through the ORM with bound
parameters. There is no place where user input is concatenated into SQL,
which is what makes SQL injection structurally impossible rather than
filtered away.
"""

from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker

# The session factory is created unbound at import time and receives its
# engine in init_engine(). That way every module can do
# "from portal.db import Session" at import time and still end up talking to
# the engine that is configured later during application startup.
_engine = None
_factory = sessionmaker(autoflush=False, expire_on_commit=False, future=True)
Session = scoped_session(_factory)


class Base(DeclarativeBase):
    """Declarative base of all portal models."""


def _sqlite_pragmas(dbapi_connection, _record):
    """Enable write ahead logging and foreign keys on every SQLite connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def init_engine(database_url):
    """Create the engine and bind the session factory, idempotent per process."""
    global _engine
    if _engine is not None:
        return _engine

    kwargs = {"future": True, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        # The scheduler thread shares the engine with the request threads.
        kwargs["connect_args"] = {"check_same_thread": False}

    _engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):
        event.listen(_engine, "connect", _sqlite_pragmas)

    _factory.configure(bind=_engine)
    return _engine


def create_all():
    """
    Create missing tables, then add missing columns.

    Das Schema waechst nur additiv, deshalb reicht dieser eine Schritt und es
    braucht kein Migrationswerkzeug. Ohne ihn waere aber jede neue Spalte eine
    stille Falle: create_all legt nur fehlende *Tabellen* an, und eine neue
    Spalte an einer bestehenden Tabelle liesse jede Abfrage darauf auflaufen.
    Eine neue Tabelle, wie api_keys, ging gut. Die erste neue Spalte haette es
    nicht getan.
    """
    Base.metadata.create_all(_engine)
    _ergaenze_spalten()


def _ergaenze_spalten():
    """
    Add columns the model knows and the database does not.

    Nur nullable Spalten ohne Vorgabewert. Alles andere verlangt in SQLite ein
    Umschreiben der Tabelle, und dann waere ein richtiges Migrationswerkzeug
    faellig statt dieser fuenfzehn Zeilen.
    """
    pruefer = inspect(_engine)
    with _engine.begin() as verbindung:
        for tabelle in Base.metadata.sorted_tables:
            if not pruefer.has_table(tabelle.name):
                continue
            vorhanden = {s["name"] for s in pruefer.get_columns(tabelle.name)}
            for spalte in tabelle.columns:
                if spalte.name in vorhanden:
                    continue
                if not spalte.nullable or spalte.server_default is not None:
                    raise RuntimeError(
                        "Spalte %s.%s laesst sich nicht nachtraeglich anlegen: "
                        "sie ist nicht nullable oder hat einen Vorgabewert. "
                        "Dafuer braucht es ein Migrationswerkzeug."
                        % (tabelle.name, spalte.name))
                typ = spalte.type.compile(_engine.dialect)
                verbindung.execute(text('ALTER TABLE "%s" ADD COLUMN "%s" %s'
                                        % (tabelle.name, spalte.name, typ)))
                print("Spalte %s.%s nachgetragen" % (tabelle.name, spalte.name),
                      flush=True)


def remove_session(_exception=None):
    """Drop the request bound session, registered as Flask teardown handler."""
    Session.remove()


@contextmanager
def session_scope():
    """Provide a transactional session for background work outside a request."""
    session = _factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
