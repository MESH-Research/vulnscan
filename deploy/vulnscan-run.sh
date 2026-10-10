#!/usr/bin/env bash
# Pull the latest vulnscan and the latest main branch of each monitored project,
# then scan each project once and notify Teams / ntfy about anything new.
#
# Run as the `vulnscan` user from cron, or as the container's main loop (see
# docs/deployment.md). Projects are listed one per line in /etc/vulnscan/projects
# as:  name  git-url  [branch]  — or, when that file is absent, in the
# VULNSCAN_PROJECTS environment variable with entries separated by newlines or
# semicolons. A project's own settings go in /etc/vulnscan/<name>.env if it
# exists; otherwise the ordinary VULNSCAN_* environment applies. State that
# records what has already been notified lives in /var/lib/vulnscan/<name>; the
# Wordfence feed cache is shared between projects in /var/cache/vulnscan.
set -u

APP="${VULNSCAN_APP:-/opt/vulnscan}"
APP_BRANCH="${VULNSCAN_APP_BRANCH:-main}"
CONF="${VULNSCAN_CONF:-/etc/vulnscan}"
PROJECTS="${VULNSCAN_PROJECTS_DIR:-/srv/vulnscan/projects}"
STATE="${VULNSCAN_STATE_DIR:-/var/lib/vulnscan}"
export VULNSCAN_CACHE_DIR="${VULNSCAN_CACHE_DIR:-/var/cache/vulnscan}"
CHANNELS="${VULNSCAN_CHANNELS:---msteams}"   # e.g. "--msteams --ntfy"
SELF_UPDATE="${VULNSCAN_SELF_UPDATE:-1}"      # 0 inside a container image built from the repo
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# Fast-forward a checkout to the tip of a branch, cloning on first use.
update_checkout() {  # dir url branch
    local dir="$1" url="$2" branch="$3"
    if [ ! -d "$dir/.git" ]; then
        git clone --quiet --depth 1 --branch "$branch" "$url" "$dir" || return 1
    fi
    git -C "$dir" fetch --quiet --depth 1 origin "$branch" \
        && git -C "$dir" reset --quiet --hard FETCH_HEAD
}

status=0

# 1. vulnscan itself
if [ "$SELF_UPDATE" != "0" ]; then
    if update_checkout "$APP" https://github.com/MESH-Research/vulnscan.git "$APP_BRANCH"; then
        (cd "$APP" && uv sync --quiet --frozen --no-dev) || { log "uv sync failed"; status=1; }
    else
        log "could not update vulnscan checkout; scanning with the current version"
        status=1
    fi
fi
VULNSCAN="$APP/.venv/bin/vulnscan"
[ -x "$VULNSCAN" ] || { log "no vulnscan binary at $VULNSCAN"; exit 1; }

# 2. the project list: a file, or the VULNSCAN_PROJECTS variable
if [ -f "$CONF/projects" ]; then
    project_list=$(cat "$CONF/projects")
elif [ -n "${VULNSCAN_PROJECTS:-}" ]; then
    project_list=$(printf '%s' "$VULNSCAN_PROJECTS" | tr ';' '\n')
else
    log "no projects: create $CONF/projects or set VULNSCAN_PROJECTS"
    exit 1
fi

# 3. each project, one after the other (never in parallel: the Wordfence feed is large)
while read -r name url branch _; do
    case "$name" in ''|'#'*) continue ;; esac
    branch="${branch:-main}"
    log "== $name ($url @ $branch)"
    if ! update_checkout "$PROJECTS/$name" "$url" "$branch"; then
        log "$name: git update failed, skipping"
        status=1
        continue
    fi
    mkdir -p "$STATE/$name"
    env_file=()
    [ -f "$CONF/$name.env" ] && env_file=(--env-file "$CONF/$name.env")
    # shellcheck disable=SC2086
    "$VULNSCAN" $CHANNELS --once "${env_file[@]}" \
        --path "$PROJECTS/$name" \
        --feed-dir "$STATE/$name"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        log "$name: vulnscan exited $rc"
        status=1
    fi
done <<< "$project_list"

exit "$status"
