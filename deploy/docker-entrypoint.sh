#!/usr/bin/env bash
# Container main process: run every project once, then sleep and repeat.
# VULNSCAN_RUN_EVERY_MINUTES (default 60) sets the gap between runs; a value of
# 0 runs once and exits, for an external scheduler. SIGTERM stops promptly.
set -u
every="${VULNSCAN_RUN_EVERY_MINUTES:-60}"
sleeper=""
trap 'if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null; fi; exit 0' TERM INT
while true; do
    /usr/local/bin/vulnscan-run
    [ "$every" = "0" ] && exit $?
    sleep "$((every * 60))" &
    sleeper=$!
    wait "$sleeper"
    sleeper=""
done
