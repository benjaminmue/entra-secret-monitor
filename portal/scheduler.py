#!/usr/bin/env python3
"""
scheduler.py

Daily scan schedule and the manual force check.

Every customer owns one minute of the day. New customers land in the middle
of the currently largest gap, so 50 tenants end up roughly half an hour
apart instead of all firing at midnight. A background thread wakes up once a
minute, collects what is due and works through it one tenant at a time with
a configurable pause. Microsoft Graph therefore never sees a burst from this
portal, no matter how many customers are configured.

A single process wide lock serialises scheduled runs and force checks, so a
button press can never overlap with the scheduler on the same tenant.
"""

import threading
from datetime import datetime, timezone

from sqlalchemy import select

from portal.db import session_scope
from portal.models import TRIGGER_MANUAL, TRIGGER_SCHEDULE, Customer
from portal.scanner import run_check

MINUTES_PER_DAY = 1440

SCAN_LOCK = threading.Lock()
_state = {"last_tick": None, "running": "", "thread": None, "stop": None}


def assign_slot(session):
    """
    Return the scan minute for a new customer: the middle of the largest gap.

    Keeps the distribution even without renumbering existing customers, which
    would otherwise move every sensor's data age on each onboarding.
    """
    used = sorted(session.execute(select(Customer.slot_minute)).scalars().all())
    if not used:
        return 0
    best_start, best_gap = used[-1], (used[0] + MINUTES_PER_DAY) - used[-1]
    for earlier, later in zip(used, used[1:]):
        if later - earlier > best_gap:
            best_start, best_gap = earlier, later - earlier
    return (best_start + best_gap // 2) % MINUTES_PER_DAY


def redistribute_slots(session):
    """Spread all customers evenly over the day, ordered by key for stability."""
    customers = session.execute(
        select(Customer).order_by(Customer.key.asc())).scalars().all()
    if not customers:
        return 0
    step = MINUTES_PER_DAY / len(customers)
    for index, customer in enumerate(customers):
        customer.slot_minute = int(index * step) % MINUTES_PER_DAY
    session.commit()
    return len(customers)


def is_due(customer, now=None):
    """
    True when the customer's slot has passed today and today's run is missing.

    Comparing against today's slot rather than a fixed interval means a
    restart catches up exactly once instead of rescanning on every boot.
    """
    if not customer.is_active:
        return False
    now = now or datetime.now(timezone.utc)
    slot_today = now.replace(hour=customer.slot_minute // 60,
                             minute=customer.slot_minute % 60,
                             second=0, microsecond=0)
    if now < slot_today:
        return False
    last = customer.last_check_at
    if last is None:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return last < slot_today


def force_check(customer_id, encryption_key, actor, history_runs=30, wait_seconds=120):
    """
    Run one scan immediately, used by the force check button and on onboarding.

    Waits for the shared lock so a manual run queues behind a scheduled one
    instead of doubling the request rate against the same tenant.
    """
    if not SCAN_LOCK.acquire(timeout=wait_seconds):
        raise TimeoutError("Ein anderer Lauf blockiert seit über %d Sekunden" % wait_seconds)
    try:
        with session_scope() as session:
            customer = session.get(Customer, customer_id)
            if customer is None:
                raise LookupError("Kunde nicht gefunden")
            _state["running"] = customer.key
            run = run_check(session, customer, encryption_key,
                            trigger=TRIGGER_MANUAL, actor=actor, history_runs=history_runs)
            return run.status, run.error_message
    finally:
        _state["running"] = ""
        SCAN_LOCK.release()


def _run_due(encryption_key, gap_seconds, history_runs, stop_event):
    """Work through every due customer, one at a time, pausing in between."""
    with session_scope() as session:
        due_ids = [c.id for c in session.execute(
            select(Customer).where(Customer.is_active.is_(True))
            .order_by(Customer.slot_minute.asc())).scalars().all() if is_due(c)]

    for index, customer_id in enumerate(due_ids):
        if stop_event.is_set():
            return
        if index and gap_seconds:
            stop_event.wait(gap_seconds)
        with SCAN_LOCK:
            with session_scope() as session:
                customer = session.get(Customer, customer_id)
                if customer is None or not is_due(customer):
                    continue
                _state["running"] = customer.key
                try:
                    run = run_check(session, customer, encryption_key,
                                    trigger=TRIGGER_SCHEDULE, actor="scheduler",
                                    history_runs=history_runs)
                    print("scan %s: %s" % (customer.key, run.status), flush=True)
                except Exception as exc:                  # noqa: BLE001
                    print("scan %s abgebrochen: %s" % (customer.key, exc), flush=True)
                finally:
                    _state["running"] = ""


def _loop(config, stop_event):
    """Scheduler thread body: tick, run what is due, sleep again."""
    while not stop_event.is_set():
        try:
            _state["last_tick"] = datetime.now(timezone.utc)
            _run_due(config.encryption_key, config.gap_seconds, config.history_runs, stop_event)
        except Exception as exc:                          # noqa: BLE001
            print("scheduler: %s" % exc, flush=True)
        stop_event.wait(config.tick_seconds)


def start(config):
    """Start the background scheduler once per process."""
    if _state["thread"] is not None:
        return _state["thread"]
    stop_event = threading.Event()
    thread = threading.Thread(target=_loop, args=(config, stop_event),
                              name="scan-scheduler", daemon=True)
    _state["stop"] = stop_event
    _state["thread"] = thread
    thread.start()
    print("Scheduler aktiv, Tick %d s, Abstand %d s" % (config.tick_seconds,
                                                        config.gap_seconds), flush=True)
    return thread


def stop():
    """Signal the scheduler thread to end, used by tests and clean shutdowns."""
    if _state["stop"] is not None:
        _state["stop"].set()
    _state["thread"] = None


def status():
    """Return a small dict describing the scheduler for the GUI footer."""
    return {
        "active": _state["thread"] is not None and _state["thread"].is_alive(),
        "last_tick": _state["last_tick"],
        "running": _state["running"],
    }
