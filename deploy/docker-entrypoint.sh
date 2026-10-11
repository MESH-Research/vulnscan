#!/usr/bin/env bash
# Container main process: run every project once, then sleep and repeat.
# VULNSCAN_RUN_EVERY_MINUTES (default 60) sets the gap between runs; a value of
# 0 runs once and exits, for an external scheduler. SIGTERM stops promptly.
# A heartbeat file in VULNSCAN_STATE_DIR records the state of the latest run
# for deploy/healthcheck.sh: "running", then "ok" or "failed <exit code>".
set -u
every="${VULNSCAN_RUN_EVERY_MINUTES:-60}"
run="${VULNSCAN_RUN_COMMAND:-/usr/local/bin/vulnscan-run}"
heartbeat="${VULNSCAN_STATE_DIR:-/var/lib/vulnscan}/.heartbeat"
sleeper=""
trap 'if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null; fi; exit 0' TERM INT
while true; do
    echo running > "$heartbeat"
    "$run"
    rc=$?
    if [ "$rc" -eq 0 ]; then echo ok > "$heartbeat"; else echo "failed $rc" > "$heartbeat"; fi
    [ "$every" = "0" ] && exit "$rc"
    sleep "$((every * 60))" &
    sleeper=$!
    wait "$sleeper"
    sleeper=""
done
