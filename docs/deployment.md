# Running on a server

This page sets up vulnscan to run unattended on a server: on a schedule it
pulls the `main` branch of each project you monitor, scans it, and posts
anything new to Microsoft Teams (or ntfy). It covers a bare-metal or VM
host where you have root and cron, and an AWS EC2 instance created from a
CloudFormation template. Both use the same layout and the same wrapper
script, [`deploy/vulnscan-run.sh`](https://github.com/MESH-Research/vulnscan/blob/main/deploy/vulnscan-run.sh).

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
| `/var/lib/vulnscan/.ssh` | deploy keys and `config` with one host alias per project |
| `/var/cache/vulnscan` | shared Wordfence feed cache |
| `/var/log/vulnscan/scan.log` | output of every run, rotated weekly |

The wrapper reads its paths from `VULNSCAN_APP`, `VULNSCAN_CONF`,
`VULNSCAN_PROJECTS_DIR`, `VULNSCAN_STATE_DIR` and `VULNSCAN_CACHE_DIR`, and
the notification flags from `VULNSCAN_CHANNELS` (default `--msteams`), so
you can move any of this without editing the script.

## Repository access

The scanner needs read access to each project. The recommended way is a
**deploy key** per repository: a read-only SSH key that never expires and
grants nothing else. GitHub allows a key to be attached to only one
repository, so each project gets its own key and its own SSH host alias
(`github.com-<name>`), and the project's URL in `/etc/vulnscan/projects`
uses that alias:

```
# name    git-url                                       branch
site-a    git@github.com-site-a:your-org/site-a.git     main
api-b     git@github.com-api-b:your-org/api-b.git       main
```

A fine-grained personal access token over HTTPS also works (one token, read
access to Contents on the chosen repositories) if you prefer a single
credential, at the cost of rotating it when it expires. Public repositories
need no credential: use their `https://` URL.

vulnscan itself is public and is cloned over HTTPS.

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
sudo install -d -o vulnscan -g vulnscan -m 700 /var/lib/vulnscan/.ssh
sudo install -d -o root -g vulnscan -m 750 /etc/vulnscan
```

### 2. Deploy keys

For each project (here `site-a`):

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
```

Then record GitHub's host key once and check that the key works:

```sh
sudo -u vulnscan -H sh -c 'ssh-keyscan -t ed25519 github.com > ~/.ssh/known_hosts'
sudo -u vulnscan -H ssh -T git@github.com-site-a      # "Hi your-org/site-a! You've successfully authenticated"
```

### 3. Configuration

```sh
sudo tee /etc/vulnscan/projects >/dev/null <<'EOT'
site-a    git@github.com-site-a:your-org/site-a.git     main
api-b     git@github.com-api-b:your-org/api-b.git       main
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

### 4. vulnscan and the wrapper

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

### 5. Cron and log rotation

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

- **Add a project:** a deploy key, a line in `/etc/vulnscan/projects`, a
  `.env`. The next run clones and scans it.
- **Upgrade vulnscan:** automatic, since every run tracks `main`. If you
  would rather stay on tagged releases, set `VULNSCAN_APP_BRANCH` in the
  cron file to a tag such as `v1.2.0`. The wrapper copies itself nowhere,
  so re-run the `install -m 755 ...` line from step 4 after a release that
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

Create the deploy keys on your own machine (the same `ssh-keygen` commands
as above, in any directory), add the public halves to GitHub, then store:

```sh
aws ssm put-parameter --name /vulnscan/projects --type String --value "$(cat projects)"
aws ssm put-parameter --name /vulnscan/site-a/env --type SecureString --value "$(cat site-a.env)"
aws ssm put-parameter --name /vulnscan/site-a/deploy-key --type SecureString --value "$(cat site-a)"
aws ssm put-parameter --name /vulnscan/api-b/env --type SecureString --value "$(cat api-b.env)"
aws ssm put-parameter --name /vulnscan/api-b/deploy-key --type SecureString --value "$(cat api-b)"
```

`projects` has the same format as `/etc/vulnscan/projects`; the user-data
writes one SSH host alias per project for which a `deploy-key` parameter
exists. Delete the private keys locally once stored. Standard parameters
hold up to 4 KB, enough for a key and a short `.env`.

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
