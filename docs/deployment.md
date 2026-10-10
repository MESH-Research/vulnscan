# Running on a server

This page sets up vulnscan to run unattended on a server: on a schedule it
pulls the `main` branch of each project you monitor, scans it, and posts
anything new to Microsoft Teams (or ntfy). It covers three hosts: a
bare-metal or VM box where you have root and cron, an AWS EC2 instance
created from a CloudFormation template, and a container on
[Coolify](https://coolify.io) (or plain Docker). All three use the same
layout and the same wrapper script,
[`deploy/vulnscan-run.sh`](https://github.com/MESH-Research/vulnscan/blob/main/deploy/vulnscan-run.sh).

## How it fits together

Every scheduled run does the following, as an unprivileged `vulnscan` user:

1. Fast-forwards the vulnscan checkout in `/opt/vulnscan` to `origin/main`
   and runs `uv sync --frozen --no-dev`, so you always scan with the
   current release.
2. For each project in `/etc/vulnscan/projects`, fast-forwards a shallow
   clone under `/srv/vulnscan/projects/<name>` to its branch tip. The scan
   reads manifests and lock files straight from the checkout, so nothing is
   installed (no `composer install`, no `npm install`). Commit your lock
   files if you want installed versions rather than constraint lower
   bounds.
3. Runs `vulnscan --msteams --once` (or whatever channels you choose) with
   that project's `.env`, and a per-project state directory under
   `/var/lib/vulnscan/<name>` so each project remembers separately which
   advisories have already been sent. The first run therefore posts
   everything currently found; after that only new advisories arrive.

Projects run one after another, never in parallel, and share one Wordfence
feed cache in `/var/cache/vulnscan`, so the feed is downloaded at most once
a day however many projects you scan.

| Path | Purpose |
|------|---------|
| `/opt/vulnscan` | vulnscan checkout and its `.venv` |
| `/usr/local/bin/vulnscan-run` | copy of `deploy/vulnscan-run.sh`, called by cron |
| `/etc/vulnscan/projects` | one project per line: `name  git-url  [branch]` |
| `/etc/vulnscan/<name>.env` | that project's settings and secrets (mode 640, `root:vulnscan`) |
| `/srv/vulnscan/projects/<name>` | shallow clone of the project |
| `/var/lib/vulnscan/<name>` | feeds, reports and `msteams-state.json` / `ntfy-state.json` |
| `/var/lib/vulnscan/.ssh` | deploy keys, private repositories only |
| `/var/cache/vulnscan` | shared Wordfence feed cache |
| `/var/log/vulnscan/scan.log` | output of every run, rotated weekly |

The wrapper reads its paths from `VULNSCAN_APP`, `VULNSCAN_CONF`,
`VULNSCAN_PROJECTS_DIR`, `VULNSCAN_STATE_DIR` and `VULNSCAN_CACHE_DIR`, and
the notification flags from `VULNSCAN_CHANNELS` (default `--msteams`), so
you can move any of this without editing the script.

## Repository access

Public repositories need no credential: list them by their `https://` URL
and every clone and fetch is anonymous.

```
# name    git-url                                   branch
site-a    https://github.com/your-org/site-a.git    main
api-b     https://github.com/your-org/api-b.git     main
```

vulnscan itself is public and is cloned the same way.

!!! note "Private repositories"
    For a private repository the cleanest credential is a **deploy key**:
    a read-only SSH key attached to that one repository, which never
    expires and grants nothing else. GitHub allows a key on only one
    repository, so each project gets its own key and its own SSH host
    alias, and its URL becomes `git@github.com-<name>:your-org/<name>.git`.
    On the bare-metal host, as the `vulnscan` user:

    ```sh
    sudo -u vulnscan -H ssh-keygen -t ed25519 -N '' -C 'vulnscan site-a' -f /var/lib/vulnscan/.ssh/site-a
    sudo cat /var/lib/vulnscan/.ssh/site-a.pub     # add as a read-only deploy key on GitHub
    sudo -u vulnscan -H tee -a /var/lib/vulnscan/.ssh/config >/dev/null <<'EOT'
    Host github.com-site-a
      HostName github.com
      User git
      IdentityFile ~/.ssh/site-a
      IdentitiesOnly yes

    EOT
    sudo -u vulnscan -H sh -c 'ssh-keyscan -t ed25519 github.com > ~/.ssh/known_hosts'
    sudo -u vulnscan -H ssh -T git@github.com-site-a      # "Hi your-org/site-a! You've successfully authenticated"
    ```

    On AWS, store the private key as the SSM parameter
    `/vulnscan/<name>/deploy-key` and the user-data writes the key and the
    host alias for you. A fine-grained personal access token over HTTPS
    (read access to Contents on the chosen repositories) also works if you
    prefer one credential, at the cost of rotating it when it expires.

## Bare metal or VM

The commands below are for Debian or Ubuntu; substitute your package
manager elsewhere. Python 3.12 is not required on the host: `uv` downloads
a private interpreter if the system one is too old.

### 1. Packages, user, directories

```sh
sudo apt-get install -y git curl cron
curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

sudo useradd --system --create-home --home-dir /var/lib/vulnscan --shell /usr/sbin/nologin vulnscan
sudo install -d -o vulnscan -g vulnscan -m 750 /opt/vulnscan /srv/vulnscan/projects /var/cache/vulnscan /var/log/vulnscan
sudo install -d -o root -g vulnscan -m 750 /etc/vulnscan
```

### 2. Configuration

```sh
sudo tee /etc/vulnscan/projects >/dev/null <<'EOT'
site-a    https://github.com/your-org/site-a.git    main
api-b     https://github.com/your-org/api-b.git     main
EOT
sudo chown root:vulnscan /etc/vulnscan/projects && sudo chmod 640 /etc/vulnscan/projects
```

Give each project its own `.env`. Start from
[`.env.example`](configuration.md) and keep it short: the webhook, the
Wordfence key for WordPress projects, and anything project-specific such as
ignored directories. The feed directory, project path and cache directory
are set by the wrapper and need not appear.

```sh
sudo tee /etc/vulnscan/site-a.env >/dev/null <<'EOT'
VULNSCAN_FEED_TITLE=site-a: vulnerable dependencies
VULNSCAN_MSTEAMS_WEBHOOK_URL=https://...
VULNSCAN_WORDFENCE_API_KEY=...
VULNSCAN_IGNORE_DIRS=web/app/plugins/graveyard
EOT
sudo chown root:vulnscan /etc/vulnscan/site-a.env && sudo chmod 640 /etc/vulnscan/site-a.env
```

Two projects can post to the same Teams channel or to different ones; each
card names the project, and the state files are separate either way.

### 3. vulnscan and the wrapper

```sh
sudo -u vulnscan -H git clone --depth 1 --branch main https://github.com/MESH-Research/vulnscan.git /opt/vulnscan
sudo -u vulnscan -H sh -c 'cd /opt/vulnscan && uv sync --frozen --no-dev'
sudo install -m 755 /opt/vulnscan/deploy/vulnscan-run.sh /usr/local/bin/vulnscan-run
```

Check that each project's webhook or topic is reachable before anything
is scanned. `--test` posts one short message to the channel and exits
without scanning or recording anything:

```sh
sudo -u vulnscan -H mkdir -p /srv/vulnscan/projects/site-a
sudo -u vulnscan -H /opt/vulnscan/.venv/bin/vulnscan --msteams --test \
  --env-file /etc/vulnscan/site-a.env --path /srv/vulnscan/projects/site-a
```

`--path` only names the project in the message, but it must exist, hence
the empty directory; the wrapper clones into it on its first run. Then run
the wrapper once by hand. This clones the projects, fetches the
Wordfence feed (a minute or two the first time) and sends the initial
backlog of notifications:

```sh
sudo -u vulnscan -H /usr/local/bin/vulnscan-run
```

Exit status is non-zero if any step failed; the log says which. To test
without posting anything, run the scan directly in report mode:

```sh
sudo -u vulnscan -H env VULNSCAN_CACHE_DIR=/var/cache/vulnscan \
  /opt/vulnscan/.venv/bin/vulnscan --text - --env-file /etc/vulnscan/site-a.env \
  --path /srv/vulnscan/projects/site-a --feed-dir /var/lib/vulnscan/site-a
```

### 4. Cron and log rotation

Hourly is a sensible default: OSV queries are cheap, and the Wordfence feed
is cached for 24 hours regardless of how often you scan. `flock -n` makes an
overlapping run exit immediately instead of queueing.

```sh
sudo tee /etc/cron.d/vulnscan >/dev/null <<'EOT'
SHELL=/bin/bash
VULNSCAN_CHANNELS=--msteams
17 * * * * vulnscan flock -n /var/lib/vulnscan/.lock /usr/local/bin/vulnscan-run >> /var/log/vulnscan/scan.log 2>&1
EOT

sudo tee /etc/logrotate.d/vulnscan >/dev/null <<'EOT'
/var/log/vulnscan/scan.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    su vulnscan vulnscan
}
EOT
```

Set `VULNSCAN_CHANNELS=--msteams --ntfy` to send to both, with the ntfy
topic and token in each project's `.env`.

### Day-to-day

- **Add a project:** a line in `/etc/vulnscan/projects` and a `.env`. The
  next run clones and scans it.
- **Upgrade vulnscan:** automatic, since every run tracks `main`. If you
  would rather stay on tagged releases, set `VULNSCAN_APP_BRANCH` in the
  cron file to a tag such as `v1.2.0`. The wrapper copies itself nowhere,
  so re-run the `install -m 755 ...` line from step 3 after a release that
  changes `deploy/vulnscan-run.sh`.
- **Re-send everything** to a channel: delete that project's
  `msteams-state.json` or `ntfy-state.json` under `/var/lib/vulnscan/<name>`
  (or run the scanner by hand with `--resend`).
- **Check on it:** `tail /var/log/vulnscan/scan.log`. Each run prints a
  header per project and the scanner's own log lines.

## AWS (CloudFormation)

[`deploy/aws-cloudformation.yaml`](https://github.com/MESH-Research/vulnscan/blob/main/deploy/aws-cloudformation.yaml)
creates one Ubuntu 24.04 arm64 instance (`t4g.micro` by default) whose
user-data performs exactly the bare-metal steps above, reading the
configuration from SSM Parameter Store. It has no inbound ports: the
security group allows outbound traffic only and you administer it with SSM
Session Manager, so there is no SSH key pair to manage. The template
also adds a 2 GB swap file (see [Sizing](#sizing)).

### 1. Put the configuration in Parameter Store

Write the `projects` file and one `.env` per project locally, then store
them:

```sh
aws ssm put-parameter --name /vulnscan/projects --type String --value "$(cat projects)"
aws ssm put-parameter --name /vulnscan/site-a/env --type SecureString --value "$(cat site-a.env)"
aws ssm put-parameter --name /vulnscan/api-b/env --type SecureString --value "$(cat api-b.env)"
```

`projects` has the same format as `/etc/vulnscan/projects`. For a private
repository add `/vulnscan/<name>/deploy-key` holding the private SSH key
(see [Repository access](#repository-access)); the user-data writes a host
alias for every project that has one. Standard parameters hold up to 4 KB.

### 2. Create the stack

```sh
aws cloudformation deploy \
  --template-file deploy/aws-cloudformation.yaml \
  --stack-name vulnscan \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides VpcId=vpc-0123456789abcdef0 SubnetId=subnet-0123456789abcdef0
```

Optional parameters: `InstanceType` (`t4g.micro`, `t4g.small`, ...),
`CronSchedule` (default `17 * * * *`, UTC), `Channels` (default
`--msteams`), `ParameterPrefix` (default `/vulnscan`). The subnet must reach
the internet (a public subnet with a public IP, or a private one behind a
NAT gateway) for GitHub, OSV, Wordfence and Teams.

The instance starts its first scan in the background as soon as user-data
finishes, so expect the initial backlog of notifications a few minutes
after the stack reports `CREATE_COMPLETE`.

### 3. Operate it

```sh
aws ssm start-session --target <instance id from the stack outputs>
sudo tail -f /var/log/vulnscan/scan.log
```

Changing a parameter does not change a running instance: either edit the
files under `/etc/vulnscan` and `/var/lib/vulnscan/.ssh` on the box, or
replace the instance (delete and re-create the stack; the only state lost
is the "already notified" record, so the first run of the new instance
re-posts the current findings). The same CloudFormation file is the natural
place to switch the instance size or schedule later.

If you use Terraform instead, the template maps directly: an
`aws_instance` with the same `user_data`, an IAM role with
`AmazonSSMManagedInstanceCore` plus `ssm:GetParameter*` on
`arn:aws:ssm:*:*:parameter/vulnscan/*`, and an egress-only security group.

## Coolify (or plain Docker)

The repository's [`Dockerfile`](https://github.com/MESH-Research/vulnscan/blob/main/Dockerfile)
builds an image whose main process is a loop: run the wrapper over every
project, sleep `VULNSCAN_RUN_EVERY_MINUTES` (default 60), repeat. The
image already contains vulnscan, so the wrapper's self-update step is off
and new vulnscan releases arrive by rebuilding the image. Three volumes
persist what matters between restarts: the "already notified" state, the
Wordfence cache and the project clones. All configuration is environment
variables, so there are no files to place.
[`deploy/docker-compose.yml`](https://github.com/MESH-Research/vulnscan/blob/main/deploy/docker-compose.yml)
declares the service and the volumes.

| Variable | Purpose |
|----------|---------|
| `VULNSCAN_PROJECTS` | the project list, entries separated by `;` (or newlines): `site-a https://github.com/your-org/site-a.git main; api-b https://github.com/your-org/api-b.git` |
| `VULNSCAN_MSTEAMS_WEBHOOK_URL` | Teams webhook, shared by every project |
| `VULNSCAN_CHANNELS` | `--msteams` (default), `--ntfy` or `--msteams --ntfy`; ntfy needs `VULNSCAN_NTFY_TOPIC` and usually `VULNSCAN_NTFY_TOKEN` |
| `VULNSCAN_WORDFENCE_API_KEY` | for WordPress projects |
| `VULNSCAN_RUN_EVERY_MINUTES` | gap between runs; `0` runs once and exits |

Any other `VULNSCAN_*` setting can be added the same way and applies to
every project. If two projects need different settings (different Teams
channels, say), mount a file at `/etc/vulnscan/<name>.env`; the wrapper
passes it to that project only. In Coolify that is a **File mount** under
Persistent Storage.

### In Coolify

1. **New resource** in the project and environment of your choice, source
   **Public Repository**, URL `https://github.com/MESH-Research/vulnscan`,
   branch `main`. (To track your own fork, or to get automatic redeploys on
   push, choose the GitHub App source instead; nothing else changes.)
2. **Build pack: Docker Compose**, base directory `/`, compose file
   `/deploy/docker-compose.yml`. Coolify reads the volumes from the file and
   creates them. Alternatively pick the **Dockerfile** build pack with the
   default Dockerfile location and add the three volumes yourself under
   Persistent Storage: `/var/lib/vulnscan`, `/var/cache/vulnscan` and
   `/srv/vulnscan/projects`.
3. The scanner serves nothing, so leave the domain empty and clear the
   exposed port if the form pre-fills one; Coolify then runs it as a plain
   worker without proxying.
4. **Environment variables:** add `VULNSCAN_PROJECTS`,
   `VULNSCAN_MSTEAMS_WEBHOOK_URL` and, for WordPress, `VULNSCAN_WORDFENCE_API_KEY`.
   Mark the webhook and the key as secrets so they are hidden in the UI.
5. **Deploy.** The first run starts immediately and posts the current
   findings for each project; the container's log, under **Logs**, shows one
   header line per project followed by the scanner's own output.

To check a webhook before the first real run, open **Terminal** on the
resource and send a test message:

```sh
mkdir -p /srv/vulnscan/projects/site-a
/opt/vulnscan/.venv/bin/vulnscan --msteams --test --path /srv/vulnscan/projects/site-a
```

Coolify rebuilds and restarts the container on **Redeploy**, which is how
you pick up a new vulnscan release; the volumes survive, so nothing is
re-notified. Memory follows the [Sizing](#sizing) section: give the
Coolify host, not the container, the headroom.

### Plain Docker

The same compose file works anywhere:

```sh
git clone https://github.com/MESH-Research/vulnscan.git && cd vulnscan
cat > deploy/.env <<'EOT'
VULNSCAN_PROJECTS=site-a https://github.com/your-org/site-a.git main; api-b https://github.com/your-org/api-b.git
VULNSCAN_MSTEAMS_WEBHOOK_URL=https://...
VULNSCAN_WORDFENCE_API_KEY=...
EOT
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml logs -f
```

## Sizing

The only part of vulnscan that needs real memory is the Wordfence feed,
used for WordPress packages. It is one JSON document covering every known
WordPress vulnerability, and it is parsed in full. Measured on the current
feed (about 41,000 records, 70 MB cached on disk):

| Stage | Peak resident memory |
|-------|---------------------|
| Interpreter with vulnscan imported | 50 MB |
| Cached feed read from disk and parsed | 340 MB |
| Re-serialised after a refresh | 360 MB |

A fresh download is heavier than reading the cache: the raw feed is larger
than the slimmed cached copy and both are held at once while it is being
trimmed, so budget 600 to 700 MB for the first run and for the daily
refresh. Scans of Python, PHP and Node.js packages that do not involve
WordPress use a few tens of megabytes.

A **t4g.micro** (2 vCPUs, 1 GB) therefore works for two projects provided
they run one after the other, which the wrapper guarantees, and provided
there is swap to absorb the refresh peak, which the template adds. Memory
is the only constraint; the CPU is idle except for a few seconds per scan,
well within the instance's burst credits. If both projects are WordPress
sites and you would rather not depend on swap, a **t4g.small** (2 GB)
removes the question for roughly twice the instance cost. If neither is
WordPress, the micro is more than enough. 10 GB of disk is ample: the
cache, two shallow clones and the virtual environment total well under
1 GB.
