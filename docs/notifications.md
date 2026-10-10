# Notifications

Notification mode keeps vulnscan running, rescans a project at a fixed
interval, and pushes a message the first time each advisory is seen for
that project. Two channels are available and can run together:

- **ntfy** (`--ntfy`): a push notification to the [ntfy](https://ntfy.sh)
  app on your phone, or any ntfy client.
- **Microsoft Teams** (`--msteams`): an Adaptive Card posted to a channel
  through an incoming webhook.

```
uv run vulnscan --ntfy
uv run vulnscan --msteams
uv run vulnscan --ntfy --msteams
```

## What a notification contains

Each notification covers one dependency and only the advisories that
channel has not seen before. It states:

- the **severity** of the worst new advisory (critical, high, medium, low
  or unknown), which also sets the ntfy priority and the Teams card colour;
- the installed version and where it was read from (lock file, pin or
  constraint);
- the **upgrade that clears every advisory**: the smallest published,
  stable, non-yanked version above the installed one that none of the
  package's advisories affect, looked up on PyPI, Packagist or
  wordpress.org, or a note that no safe version exists yet;
- the latest release and whether it is still affected;
- for each advisory: its id linked to the full record, the CVE id linked to
  the NVD entry, severity with the CVSS vector, a summary and description,
  the **lowest fixed version above the installed one and whether it is
  actually available** on the registry, and the publication date;
- every manifest that declares the package and the constraint written there.

If the registry cannot be reached, the notification still goes out with the
upgrade advice marked as unknown.

## Running

Each cycle:

1. scans the project exactly as the TUI would;
2. for each channel, compares every (dependency, advisory) pair against
   that channel's sent-state file;
3. sends one notification per dependency that has unsent advisories;
4. records the ids the service accepted;
5. sleeps for `VULNSCAN_INTERVAL_MINUTES` (override with
   `--interval MINUTES`).

The first run has no state, so it sends everything currently found. After
that only genuinely new advisories arrive. Because state is kept per
channel (`ntfy-state.json`, `msteams-state.json` in the feed directory),
adding a channel later gives it the full backlog while the other stays
quiet. If a service cannot be reached, nothing is recorded for the failed
messages and they are retried on the next cycle. A scan failure (OSV or
Wordfence unreachable) is logged and the loop carries on; it never exits on
its own. Progress is logged to stderr with timestamps, so it suits a
systemd service or a `screen` session.

Because the Wordfence feed is cached and only refreshed when it expires, a
short interval does not hammer the API.

### Re-sending everything

Send `SIGUSR1` to the running process and it immediately rescans and pushes
every current finding to every channel again, regardless of state:

```
kill -USR1 <pid of the vulnscan process>
```

To do the same at start-up, add `--resend`. `SIGINT` (Ctrl-C) and `SIGTERM`
stop the loop cleanly.

### Checking a channel works

```
uv run vulnscan --ntfy --test
uv run vulnscan --msteams --test
uv run vulnscan --ntfy --msteams --test
```

`--test` sends a single short message to each selected channel, naming the
project it would report on, and exits. Nothing is scanned and no state file
is written, so the next real run still delivers every current finding. The
exit status is 0 if every channel accepted the message and 1 otherwise, with
the service's answer printed to stderr, which makes it a quick way to
confirm a topic name, an access token or a Teams webhook URL before
scheduling anything.

### One cycle at a time (cron)

```
*/30 * * * * cd /srv/vulnscan && uv run vulnscan --ntfy --msteams --once
```

`--once` runs a single scan-and-notify cycle and exits 0, or 1 if the scan
failed. Combine with `--resend` to push everything.

## ntfy

In `.env`:

```
VULNSCAN_NTFY_SERVER=https://ntfy.sh          # or your own server
VULNSCAN_NTFY_TOPIC=mysite-vulns
VULNSCAN_NTFY_TOKEN=tk_xxxxxxxxxxxxxxxx         # access token, or:
#VULNSCAN_NTFY_USER=me
#VULNSCAN_NTFY_PASSWORD=secret
```

Use a token (`Bearer` authentication) or a user and password (basic
authentication). If both are set the token wins. Topics on the public
`ntfy.sh` are open to anyone who guesses the name, so pick an unguessable
one or run your own server with access control.

A message looks like this. Title: `authlib 1.2.0: 2 new advisories`

```
Project: mysite
Severity: CRITICAL
Upgrade to: 1.4.0 (available on PyPI, clears all)

GHSA-xxxx-xxxx-xxxx (CVE-2025-1234) [CRITICAL]: JWT algorithm confusion
  fixed in: 1.3.1 (available on PyPI)
GHSA-yyyy-yyyy-yyyy [HIGH]: Second issue
  fixed in: 1.4.0 (available on PyPI)

Declared in: requirements/base.txt, requirements/production.txt
```

Priority follows the worst severity (critical = urgent, high = high,
medium or unknown = default, low = low), the tags carry the severity, and
tapping the notification opens the first advisory.

## Microsoft Teams

Teams receives webhooks through the **Workflows** app:

1. In Teams, open the channel, choose **More options (…) → Workflows**.
2. Pick the **Send webhook alerts to a channel** template (or build a flow
   from the "When a Teams webhook request is received" trigger that posts
   the received Adaptive Card).
3. Save it and copy the webhook URL into `.env`:

```
VULNSCAN_MSTEAMS_WEBHOOK_URL=https://prod-00.westus.logic.azure.com:443/workflows/...
```

Anyone with the URL can post to the channel, so keep it out of version
control. Legacy Microsoft 365 connector URLs (`*.webhook.office.com`) are
accepted too while they still work.

Each notification is one message carrying one Adaptive Card, kept short
enough to take in at a glance:

- a bold headline, coloured by severity (red for critical and high, amber
  for medium, green for low): `New vulnerability on mysite: authlib 1.2.0:
  2 new advisories`;
- a subtle line with the severity, ecosystem and the manifests that declare
  the package;
- three facts: the installed version, the upgrade that clears every
  advisory and whether it is available, and the latest release;
- one line per advisory, most severe first, with the severity, the advisory
  id linked to its full record, the CVE ids linked to NVD, a one-line
  summary and the lowest fixed version. Advisory descriptions are never
  included and any Markdown in summaries is stripped, so the text stays one
  size;
- buttons that open the first three advisories.

At most six advisories are listed; a final line says how many more there
are. Posts are spaced to stay under the webhook's four-per-second limit.

## Running as a service

A minimal systemd unit:

```
[Unit]
Description=vulnscan watch for mysite
After=network-online.target

[Service]
WorkingDirectory=/srv/vulnscan
ExecStart=/usr/local/bin/uv run vulnscan --ntfy --msteams --path /srv/mysite
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`systemctl reload vulnscan-mysite` then re-sends every current finding.
