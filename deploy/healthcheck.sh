#!/usr/bin/env bash
# Container health check: healthy while the scan loop keeps completing runs.
#
# The entrypoint writes $VULNSCAN_STATE_DIR/.heartbeat before each run ("running")
# and after it ("ok" or "failed <code>"). The container is unhealthy when no run
# has happened yet, when the last run failed, or when the file is older than two
# run intervals plus a ten-minute grace period (a hung run or a dead loop).
set -u
state="${VULNSCAN_STATE_DIR:-/var/lib/vulnscan}"
every="${VULNSCAN_RUN_EVERY_MINUTES:-60}"
heartbeat="$state/.heartbeat"

if [ ! -f "$heartbeat" ]; then
    echo "no run has completed yet"
    exit 1
fi
read -r status detail < "$heartbeat"
now=$(date +%s)
modified=$(stat -c %Y "$heartbeat" 2>/dev/null || stat -f %m "$heartbeat")
age=$((now - modified))
limit=$((every * 2 * 60 + 600))
if [ "$age" -gt "$limit" ]; then
    echo "last run ${age}s ago (limit ${limit}s): the scan loop looks stuck"
    exit 1
fi
if [ "$status" = "failed" ]; then
    echo "last run failed (exit ${detail:-?}), ${age}s ago"
    exit 1
fi
echo "$status, ${age}s ago"
exit 0
