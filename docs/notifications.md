# Notifications with ntfy

ntfy mode keeps vulnscan running, rescans a project at a fixed interval, and
pushes a notification through [ntfy](https://ntfy.sh) the first time each
advisory is seen for that project. Install the ntfy app on your phone (or
use the web app), subscribe to a topic, and you have a real-time pager for
new vulnerabilities in your dependencies.

## Configuration

In `.env`:

```
VULNSCAN_PROJECT_PATH=/srv/mysite
VULNSCAN_NTFY_SERVER=https://ntfy.sh          # or your own server
VULNSCAN_NTFY_TOPIC=mysite-vulns
VULNSCAN_NTFY_TOKEN=tk_xxxxxxxxxxxxxxxx         # access token, or:
#VULNSCAN_NTFY_USER=me
#VULNSCAN_NTFY_PASSWORD=secret
VULNSCAN_NTFY_INTERVAL_MINUTES=60
```

Use a token (`Bearer` authentication) or a user and password (basic
authentication). If both are set the token wins. Topics on the public
`ntfy.sh` are open to anyone who guesses the name, so pick an unguessable
one or run your own server with access control.

## Running

```
uv run vulnscan --ntfy
```

Each cycle:

1. scans the project exactly as the TUI would;
2. compares every (dependency, advisory) pair against the sent-state file
   (`VULNSCAN_NTFY_STATE_FILE`, default `ntfy-state.json` in the feed
   directory);
3. sends one notification per dependency that has advisories not yet sent,
   listing only those new advisories;
4. records the ids it successfully sent;
5. sleeps for `VULNSCAN_NTFY_INTERVAL_MINUTES` (override with
   `--interval MINUTES`).

The first run has no state, so it sends everything currently found. After
that only genuinely new advisories arrive. If the ntfy server cannot be
reached, nothing is recorded for the failed messages and they are retried
on the next cycle. A scan failure (OSV or Wordfence unreachable) is logged
and the loop carries on; it never exits on its own. Progress is logged to
stderr with timestamps, so it suits a systemd service or a `screen`
session.

Because the Wordfence feed is cached and only refreshed when it expires, a
short interval does not hammer the API: a one-minute interval makes one
request to OSV per cycle and almost none to Wordfence.

## Re-sending everything

Send `SIGUSR1` to the running process and it immediately rescans and pushes
every current finding again, regardless of state:

```
kill -USR1 $(pgrep -f 'vulnscan --ntfy')
```

To do the same at start-up, add `--resend`. `SIGINT` (Ctrl-C) and `SIGTERM`
stop the loop cleanly.

## One cycle at a time (cron)

If you would rather schedule it yourself:

```
*/30 * * * * cd /srv/vulnscan && uv run vulnscan --ntfy --once
```

`--once` runs a single scan-and-notify cycle and exits 0, or 1 if the scan
failed. Combine with `--resend` to push everything.

## What a notification looks like

Title: `authlib 1.2.0: 2 new advisories`

Body:

```
Project: mysite
Severity: CRITICAL

GHSA-xxxx-xxxx-xxxx (CVE-2025-1234) [CRITICAL]: JWT algorithm confusion
  fixed in: 1.3.1
GHSA-yyyy-yyyy-yyyy [HIGH]: Second issue
  fixed in: 1.4.0

Declared in: requirements/base.txt, requirements/production.txt
```

The notification's priority follows the worst severity among the *new*
advisories (critical = urgent, high = high, medium or unknown = default,
low = low), its tags carry the severity, and tapping it opens the first
advisory. One topic can serve several projects: the project name is in the
body and ids are tracked per project.

## Running as a service

A minimal systemd unit:

```
[Unit]
Description=vulnscan watch for mysite
After=network-online.target

[Service]
WorkingDirectory=/srv/vulnscan
ExecStart=/usr/local/bin/uv run vulnscan --ntfy --path /srv/mysite
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`systemctl reload vulnscan-mysite` then re-sends every current finding.
