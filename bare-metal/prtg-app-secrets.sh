#!/bin/bash
# PRTG SSH Script Advanced wrapper for the bare metal installation.
# Deploy to /var/prtg/scriptsxml/prtg-app-secrets.sh on the monitored host.
# PRTG runs it over SSH and reads the PRTG XML from stdout.
#
# Optional sensor parameters are passed through, for example:
#   --tenant contoso --include-sp --warn 45

set -u

ENV_FILE="/etc/entra-secret-monitor/monitor.env"
CLI="/opt/entra-secret-monitor/cli.py"

if [ ! -r "$ENV_FILE" ]; then
    echo '<?xml version="1.0" encoding="UTF-8" ?>'
    echo "<prtg><error>1</error><text>Env file $ENV_FILE not readable</text></prtg>"
    exit 0
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

exec /usr/bin/python3 "$CLI" --format prtg "$@"
