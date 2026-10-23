"""Diagnostic logging: HTTP exchanges as curl commands, control flow and internals.

Everything goes through the standard :mod:`logging` framework under the ``vulnscan``
logger hierarchy, so ``logging.getLogger("vulnscan.osv")`` and friends behave as any
Python developer expects. :func:`configure` attaches one file handler and sets the
logger levels for the requested verbosity:

1. ``LEVEL_HTTP``: every outgoing HTTP request and its response, each with a ``curl``
   command that replays it (logger ``vulnscan.http``), plus warnings and errors.
2. ``LEVEL_FLOW``: additionally the ``INFO`` records that trace control flow through
   scanning, remediation, preflight and notifications.
3. ``LEVEL_INTERNAL``: additionally ``DEBUG`` records from vulnscan and from every
   third-party library, and a traceback for any uncaught exception.

Secrets never reach the log: :func:`secrets_from_settings` maps each configured
credential to the shell variable that holds it, and both the header lines and the
curl commands are written with that variable in place of the value.
"""

from __future__ import annotations

import base64
import json
import logging
import platform
import shlex
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from itertools import count
from pathlib import Path
from typing import Any

import httpx

from vulnscan import __version__, activity
from vulnscan.config import Settings

LEVEL_HTTP = 1
"""Every outgoing HTTP request and its response, each with a curl command."""
LEVEL_FLOW = 2
"""Additionally, control flow through scanning, remediation, preflight and notifying."""
LEVEL_INTERNAL = 3
"""Additionally, third-party library internals and full tracebacks."""
MAX_LEVEL = LEVEL_INTERNAL
DEFAULT_LOG_FILE = "debug.log"

RESPONSE_BODY_LIMIT = 16 * 1024
"""Response bodies longer than this are cut in the log; request bodies never are."""

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
INDENT = "    "

LEVEL_NAMES = {
    LEVEL_HTTP: "HTTP requests and responses",
    LEVEL_FLOW: "HTTP + control flow",
    LEVEL_INTERNAL: "HTTP + control flow + library internals and tracebacks",
}

_SKIPPED_HEADERS = frozenset({"host", "content-length", "connection", "accept-encoding"})

_APP_LOGGER = "vulnscan"
_HTTP_LOGGER = "vulnscan.http"
_SELF_LOGGER = "vulnscan.debug"

log = logging.getLogger(_HTTP_LOGGER)
_self_log = logging.getLogger(_SELF_LOGGER)


@dataclass
class _State:
    level: int = 0
    handler: logging.Handler | None = None
    owner: logging.Logger | None = None
    secrets: dict[str, str] = field(default_factory=dict)
    saved_levels: dict[str, int] = field(default_factory=dict)
    previous_excepthook: Any = None
    sequence: Any = field(default_factory=lambda: count(1))


_state = _State()


# -- rendering ------------------------------------------------------------------------


def _escape_double_quoted(text: str) -> str:
    out = text.replace("\\", "\\\\")
    for char in ('"', "$", "`"):
        out = out.replace(char, "\\" + char)
    return out


def _shell_quote(text: str, secrets: Mapping[str, str]) -> str:
    """Quote ``text`` for a POSIX shell, writing each secret as its shell expression.

    Text without secrets is single-quoted, which keeps every character literal. Text
    containing a secret is double-quoted with the other shell characters escaped, so
    the variable expands and everything else stays as written.
    """
    hits = [(value, expr) for value, expr in secrets.items() if value and value in text]
    if not hits:
        return shlex.quote(text)
    escaped = _escape_double_quoted(text)
    for value, expr in sorted(hits, key=lambda hit: len(hit[0]), reverse=True):
        escaped = escaped.replace(_escape_double_quoted(value), expr)
    return f'"{escaped}"'


def _redact(text: str, secrets: Mapping[str, str]) -> str:
    for value, expr in sorted(secrets.items(), key=lambda item: len(item[0]), reverse=True):
        if value:
            text = text.replace(value, expr)
    return text


def _request_body(request: httpx.Request) -> bytes | None:
    try:
        return request.content
    except httpx.RequestNotRead:
        return None


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def render_curl(request: httpx.Request, secrets: Mapping[str, str] | None = None) -> str:
    """A ``curl`` command line that replays ``request``.

    The command is one line, safe to paste into a shell. Headers that curl computes
    itself (``Host``, ``Content-Length``) are left out. Configured secrets appear as
    shell variables (``$VULNSCAN_WORDFENCE_API_KEY``) that expand when exported.
    """
    secrets = secrets or {}
    parts = ["curl", "-sS"]
    if request.method.upper() != "GET":
        parts += ["-X", request.method.upper()]
    parts.append(_shell_quote(str(request.url), secrets))
    for raw_name, raw_value in request.headers.raw:
        name = raw_name.decode("ascii", errors="replace")
        if name.lower() in _SKIPPED_HEADERS:
            continue
        value = raw_value.decode("utf-8", errors="replace")
        parts += ["-H", _shell_quote(f"{name}: {value}", secrets)]
    body = _request_body(request)
    if body:
        parts += ["--data-binary", _shell_quote(_decode(body), secrets)]
    return " ".join(parts)


def _format_body(content: bytes, content_type: str, limit: int | None) -> list[str]:
    """Lines describing a body: pretty JSON when it fits, otherwise the raw text, cut."""
    total = len(content)
    if total == 0:
        return []
    shown = content if limit is None or total <= limit else content[:limit]
    text = _decode(shown)
    looks_like_json = text.lstrip()[:1] in ("{", "[")
    if ("json" in content_type or looks_like_json) and len(shown) == total:
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    note = f"body ({total} bytes)"
    if len(shown) < total:
        note = f"body (truncated to {len(shown)} of {total} bytes)"
    lines = [note + ":"]
    lines.extend("  " + line for line in text.splitlines() or [""])
    return lines


def _join(lines: list[str]) -> str:
    return ("\n" + INDENT).join(lines)


# -- the client -----------------------------------------------------------------------


class _Tracker:
    """Mutable progress of one transfer; publishes an immutable snapshot on every change."""

    def __init__(self, transfer: activity.Transfer) -> None:
        self.transfer = transfer
        self._lock = threading.Lock()

    def _update(self, **changes: Any) -> None:
        with self._lock:
            if self.transfer.done:
                return
            self.transfer = replace(self.transfer, **changes)
            snapshot = self.transfer
        activity.publish(snapshot)

    def headers(self, response: httpx.Response) -> None:
        length = response.headers.get("content-length")
        total = int(length) if length and length.isdigit() else None
        self._update(status=response.status_code, total=total)

    def progress(self, count: int) -> None:
        self._update(received=self.transfer.received + count)

    def finish(self) -> None:
        self._update(finished=time.monotonic())

    def fail(self, exc: BaseException) -> None:
        error = _redact(f"{type(exc).__name__}: {exc}", _state.secrets)
        self._update(error=error, finished=time.monotonic())


class _ProgressStream(httpx.SyncByteStream):
    """Wraps a response's byte stream to count what arrives and notice when it closes."""

    def __init__(self, inner: httpx.SyncByteStream, tracker: _Tracker) -> None:
        self._inner = inner
        self._tracker = tracker

    def __iter__(self):
        for chunk in self._inner:
            self._tracker.progress(len(chunk))
            yield chunk

    def close(self) -> None:
        self._inner.close()
        self._tracker.finish()


class Client(httpx.Client):
    """An :class:`httpx.Client` that reports every exchange and records it when debugging.

    A drop-in replacement: construct it exactly as ``httpx.Client``. Every request is
    published to :mod:`vulnscan.activity` as it starts, answers, streams in and ends,
    which is what the TUI's activity panel shows. When a debug log is configured the
    request, the response and a replaying ``curl`` command are written to it as well.
    """

    def send(
        self, request: httpx.Request, *, stream: bool = False, **kwargs: Any
    ) -> httpx.Response:
        logging_on = is_active()
        sequence = next(_state.sequence) if logging_on else 0
        started = time.perf_counter()
        tracker = _Tracker(
            activity.Transfer(
                id=activity.next_id(),
                method=request.method,
                url=_redact(str(request.url), _state.secrets),
                started=time.monotonic(),
            )
        )
        activity.publish(tracker.transfer)
        if logging_on:
            self._log_request(sequence, request)
        try:
            response = super().send(request, stream=True, **kwargs)
        except Exception as exc:
            tracker.fail(exc)
            if logging_on:
                log.debug(
                    "#%d %s %s failed after %.2f s: %s: %s",
                    sequence,
                    request.method,
                    _redact(str(request.url), _state.secrets),
                    time.perf_counter() - started,
                    type(exc).__name__,
                    _redact(str(exc), _state.secrets),
                )
            raise
        tracker.headers(response)
        response.stream = _ProgressStream(response.stream, tracker)
        if stream:
            return response
        try:
            response.read()
        except BaseException as exc:
            tracker.fail(exc)
            response.close()
            raise
        tracker.finish()
        if logging_on:
            self._log_response(sequence, request, response, time.perf_counter() - started)
        return response

    @staticmethod
    def _log_request(sequence: int, request: httpx.Request) -> None:
        secrets = _state.secrets
        lines = [f"#{sequence} {request.method} {_redact(str(request.url), secrets)}"]
        for raw_name, raw_value in request.headers.raw:
            name = raw_name.decode("ascii", errors="replace")
            if name.lower() in _SKIPPED_HEADERS:
                continue
            value = _redact(raw_value.decode("utf-8", errors="replace"), secrets)
            lines.append(f"> {name}: {value}")
        body = _request_body(request)
        if body:
            lines.append(f"> body: {len(body)} bytes (see the curl command)")
        lines.append("$ " + render_curl(request, secrets))
        log.debug(_join(lines))

    @staticmethod
    def _log_response(
        sequence: int, request: httpx.Request, response: httpx.Response, elapsed: float
    ) -> None:
        secrets = _state.secrets
        reason = response.reason_phrase or ""
        lines = [
            f"#{sequence} {response.status_code} {reason} <- {request.method} "
            f"{_redact(str(request.url), secrets)} in {elapsed:.2f} s"
        ]
        for hop in response.history:
            lines.append(f"via {hop.status_code} {_redact(str(hop.url), secrets)}")
        for name, value in response.headers.items():
            lines.append(f"< {name}: {_redact(value, secrets)}")
        if response.is_stream_consumed or response.is_closed:
            try:
                content = response.content
            except httpx.ResponseNotRead:
                content = None
            if content is not None:
                body_lines = _format_body(
                    content, response.headers.get("content-type", ""), RESPONSE_BODY_LIMIT
                )
                lines.extend("< " + line if i == 0 else line for i, line in enumerate(body_lines))
        else:
            lines.append("< body: streamed, not recorded")
        log.debug(_join(lines))


# -- configuration --------------------------------------------------------------------


def secrets_from_settings(settings: Settings) -> dict[str, str]:
    """Map every configured secret to the shell expression that stands in for it.

    Keys are the secret values, so they can be searched for; values are what to
    write instead, such as ``$VULNSCAN_NVD_API_KEY``. ntfy basic authentication is
    sent base64-encoded, so that encoding is mapped to an expression that rebuilds
    it from ``VULNSCAN_NTFY_USER`` and ``VULNSCAN_NTFY_PASSWORD``.
    """
    pairs = [
        (settings.wordfence_api_key, "$VULNSCAN_WORDFENCE_API_KEY"),
        (settings.nvd_api_key, "$VULNSCAN_NVD_API_KEY"),
        (settings.ntfy_token, "$VULNSCAN_NTFY_TOKEN"),
        (settings.ntfy_password, "$VULNSCAN_NTFY_PASSWORD"),
        (settings.msteams_webhook_url, "$VULNSCAN_MSTEAMS_WEBHOOK_URL"),
    ]
    if settings.ntfy_user:
        credentials = f"{settings.ntfy_user}:{settings.ntfy_password}".encode()
        pairs.append(
            (
                base64.b64encode(credentials).decode("ascii"),
                '$(printf %s "$VULNSCAN_NTFY_USER:$VULNSCAN_NTFY_PASSWORD" | base64 | tr -d "\\n")',
            )
        )
    return {value: expr for value, expr in pairs if value}


def is_active() -> bool:
    """Whether :func:`configure` is in effect."""
    return _state.handler is not None


def _remember_level(logger: logging.Logger) -> None:
    _state.saved_levels.setdefault(logger.name, logger.level)


def _excepthook(exc_type, exc, tb) -> None:
    _self_log.critical("uncaught exception", exc_info=(exc_type, exc, tb))
    previous = _state.previous_excepthook or sys.__excepthook__
    previous(exc_type, exc, tb)


def configure(
    level: int,
    path: Path,
    *,
    secrets: Mapping[str, str] | None = None,
    argv: Sequence[str] | None = None,
) -> None:
    """Start writing the debug log at ``level`` (1 to 3) to ``path``.

    Calling it again replaces the previous configuration. Levels 1 and 2 attach the
    file to the ``vulnscan`` logger only; level 3 attaches it to the root logger so
    that every library's records are kept too. The file is opened for appending and
    each run starts with a banner.

    Raises:
        ValueError: if ``level`` is outside 1 to 3.
    """
    if not LEVEL_HTTP <= level <= MAX_LEVEL:
        raise ValueError(f"debug level must be between {LEVEL_HTTP} and {MAX_LEVEL}, not {level}")
    reset()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.setLevel(logging.DEBUG)

    app = logging.getLogger(_APP_LOGGER)
    root = logging.getLogger()
    for logger in (app, root, log, _self_log):
        _remember_level(logger)
    if level >= LEVEL_INTERNAL:
        owner = root
        root.setLevel(logging.DEBUG)
        app.setLevel(logging.NOTSET)
        _state.previous_excepthook = sys.excepthook
        sys.excepthook = _excepthook
    else:
        owner = app
        app.setLevel(logging.WARNING if level == LEVEL_HTTP else logging.INFO)
    log.setLevel(logging.DEBUG)
    _self_log.setLevel(logging.INFO)
    owner.addHandler(handler)

    _state.level = level
    _state.handler = handler
    _state.owner = owner
    _state.secrets = dict(secrets or {})
    _state.sequence = count(1)
    _banner(level, path, argv)


def _banner(level: int, path: Path, argv: Sequence[str] | None) -> None:
    _self_log.info(
        "vulnscan %s debug log, level %d (%s), started %s",
        __version__,
        level,
        LEVEL_NAMES[level],
        datetime.now().astimezone().isoformat(timespec="seconds"),
    )
    if argv:
        _self_log.info("command: %s", " ".join(shlex.quote(a) for a in argv))
    _self_log.info(
        "python %s on %s; httpx %s; log file %s",
        platform.python_version(),
        platform.platform(),
        httpx.__version__,
        path,
    )
    _self_log.info(
        "levels: 1 = HTTP requests and responses with a curl command for each; "
        "2 = also control flow; 3 = also library internals and tracebacks"
    )
    names = sorted({expr for expr in _state.secrets.values() if expr.startswith("$VULNSCAN_")})
    if names:
        _self_log.info(
            "secrets: %s are written as shell variables; export them "
            "(for example `set -a; . ./.env; set +a`) before pasting a curl command",
            ", ".join(name.lstrip("$") for name in names),
        )
    _self_log.info("-" * 78)


def reset() -> None:
    """Undo :func:`configure`: detach the file, restore logger levels and the hook."""
    if _state.handler is not None and _state.owner is not None:
        _state.owner.removeHandler(_state.handler)
        _state.handler.close()
    for name, level in _state.saved_levels.items():
        logging.getLogger(name).setLevel(level)
    if _state.previous_excepthook is not None:
        sys.excepthook = _state.previous_excepthook
    _state.level = 0
    _state.handler = None
    _state.owner = None
    _state.secrets = {}
    _state.saved_levels = {}
    _state.previous_excepthook = None
