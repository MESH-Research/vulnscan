# vulnscan as a long-running scanner: pulls the monitored projects, scans them
# and notifies Teams / ntfy, every VULNSCAN_RUN_EVERY_MINUTES. See
# docs/deployment.md for Coolify and plain Docker instructions.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/vulnscan --shell /usr/sbin/nologin vulnscan \
    && install -d -o vulnscan -g vulnscan /opt/vulnscan /srv/vulnscan/projects /var/cache/vulnscan /etc/vulnscan

WORKDIR /opt/vulnscan
COPY --chown=vulnscan:vulnscan pyproject.toml uv.lock README.md LICENSE __version__.py ./
COPY --chown=vulnscan:vulnscan src ./src
USER vulnscan
RUN uv sync --frozen --no-dev --compile-bytecode
USER root
COPY deploy/vulnscan-run.sh /usr/local/bin/vulnscan-run
COPY deploy/docker-entrypoint.sh /usr/local/bin/vulnscan-entrypoint
RUN chmod 755 /usr/local/bin/vulnscan-run /usr/local/bin/vulnscan-entrypoint
USER vulnscan

ENV VULNSCAN_SELF_UPDATE=0 \
    VULNSCAN_CACHE_DIR=/var/cache/vulnscan \
    VULNSCAN_STATE_DIR=/var/lib/vulnscan \
    VULNSCAN_PROJECTS_DIR=/srv/vulnscan/projects \
    VULNSCAN_CONF=/etc/vulnscan \
    VULNSCAN_CHANNELS=--msteams \
    VULNSCAN_RUN_EVERY_MINUTES=60 \
    PYTHONUNBUFFERED=1

VOLUME ["/var/lib/vulnscan", "/var/cache/vulnscan", "/srv/vulnscan/projects"]
CMD ["/usr/local/bin/vulnscan-entrypoint"]
