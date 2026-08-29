#!/usr/bin/env python3
"""
cli.py

One-shot command line interface of the Entra ID credential expiry monitor.

Runs a scan for one tenant and prints PRTG XML, JSON or a readable table,
or pushes the XML to a PRTG HTTP Push Data Advanced sensor.

  python3 cli.py --format text
  python3 cli.py --tenant contoso --format prtg
  python3 cli.py --tenant contoso --push https://prtg.example.com:5050/TOKEN
"""

import argparse
import json
import sys
from dataclasses import replace

import graph


def parse_args(argv=None):
    """Define and parse the command line arguments."""
    parser = argparse.ArgumentParser(
        description="Entra ID App Secret und Zertifikat Ablauf-Monitoring")
    parser.add_argument("--tenant", default=None,
                        help="Tenant-Key aus TENANTS bzw. tenants.json")
    parser.add_argument("--format", choices=["prtg", "json", "text"], default="prtg")
    parser.add_argument("--warn", type=int, default=None, help="Warnschwelle in Tagen")
    parser.add_argument("--error", type=int, default=None, help="Fehlerschwelle in Tagen")
    parser.add_argument("--filter", default=None,
                        help="nur Apps deren Anzeigename diesen Text enthaelt")
    parser.add_argument("--exclude", default=None,
                        help="Apps ausschliessen, kommagetrennte Textbausteine")
    parser.add_argument("--include-sp", action="store_true", default=None,
                        help="Service Principals / Enterprise Apps mit einbeziehen")
    parser.add_argument("--show-expired", action="store_true", default=None,
                        help="bereits abgelaufene Credentials ebenfalls ausgeben")
    parser.add_argument("--max-channels", type=int, default=None,
                        help="PRTG unterstützt max. 50 Kanäle pro Sensor")
    parser.add_argument("--push", default=None,
                        help="URL eines HTTP Push Data Advanced Sensors")
    parser.add_argument("--list-tenants", action="store_true",
                        help="konfigurierte Tenants ausgeben und beenden")
    return parser.parse_args(argv)


# Kommandozeilenargument -> Feld in TenantConfig. Argumente, die None sein
# koennen, werden nur bei einem Wert uebernommen.
_OVERRIDABLE = (("warn", "warn_days"), ("error", "error_days"),
                ("filter", "app_filter"), ("exclude", "app_exclude"),
                ("max_channels", "max_channels"), ("push", "push_url"))


def apply_overrides(cfg, args):
    """
    Let command line arguments win over the configured tenant defaults.

    Copies through dataclasses.replace rather than assigning fields, so
    __post_init__ runs and its invariants, above all the channel limit, hold for
    CLI runs the same way they do for requests.
    """
    changes = {}
    for arg_name, field in _OVERRIDABLE:
        value = getattr(args, arg_name)
        if value is not None:
            changes[field] = value
    # Die beiden Schalter kennen kein None, gesetzt heisst an.
    if args.include_sp:
        changes["include_sp"] = True
    if args.show_expired:
        changes["show_expired"] = True
    return replace(cfg, **changes) if changes else cfg


def select_tenant(tenants, wanted):
    """Pick the requested tenant, or the only one when none was requested."""
    if wanted:
        if wanted not in tenants:
            raise graph.GraphError("Tenant '%s' nicht konfiguriert (vorhanden: %s)"
                                   % (wanted, ", ".join(sorted(tenants))))
        return tenants[wanted]
    if len(tenants) == 1:
        return next(iter(tenants.values()))
    raise graph.GraphError("Mehrere Tenants konfiguriert, bitte --tenant angeben (%s)"
                           % ", ".join(sorted(tenants)))


def main(argv=None):
    """Entry point: scan one tenant and emit the requested output format."""
    args = parse_args(argv)
    try:
        tenants = graph.load_tenants()
        if args.list_tenants:
            for key, cfg in sorted(tenants.items()):
                print("%-20s %s" % (key, cfg.display_name))
            return 0
        cfg = apply_overrides(select_tenant(tenants, args.tenant), args)
        result = graph.scan_tenant(cfg)
    except Exception as exc:                              # noqa: BLE001
        if args.format == "prtg" and not args.push:
            print(graph.render_prtg_error("%s: %s" % (type(exc).__name__, exc)))
            return 0                                      # PRTG wertet <error> aus
        print("FEHLER: %s" % exc, file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.format == "text":
        print(graph.render_text(result, cfg))
        return 0

    xml = graph.render_prtg(result, cfg)
    if cfg.push_url:
        try:
            graph.push_to_prtg(cfg.push_url, xml)
        except Exception as exc:                          # noqa: BLE001
            print("Push fehlgeschlagen: %s" % exc, file=sys.stderr)
            return 2
        return 0
    print(xml)
    return 0


if __name__ == "__main__":
    sys.exit(main())
