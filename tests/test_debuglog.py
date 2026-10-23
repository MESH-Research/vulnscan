import base64
import json
import logging
import re
import shlex
import sys
from pathlib import Path

import httpx
import pytest

from vulnscan import __version__, debuglog
from vulnscan.config import load_settings
from vulnscan.models import PYPI, Dependency
from vulnscan.msteams import TeamsClient
from vulnscan.ntfy import NtfyClient, NtfyMessage
from vulnscan.nvd import NVDClient
from vulnscan.osv import OSVClient
from vulnscan.registry import RegistryClient
from vulnscan.wordfence import WordfenceClient


@pytest.fixture(autouse=True)
def _clean_logging():
    debuglog.reset()
    yield
    debuglog.reset()


def _request(
    method="POST",
    url="https://api.osv.dev/v1/querybatch",
    headers=None,
    json_body=None,
) -> httpx.Request:
    return httpx.Request(method, url, headers=headers or {}, json=json_body)


def _client(handler, **kwargs) -> httpx.Client:
    return debuglog.Client(transport=httpx.MockTransport(handler), **kwargs)


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


# --- render_curl ---------------------------------------------------------------------------


def test_render_curl_replays_method_url_headers_and_body():
    request = _request(
        headers={"User-Agent": "vulnscan/test", "Accept": "application/json"},
        json_body={"queries": [{"package": {"name": "requests", "ecosystem": "PyPI"}}]},
    )
    argv = shlex.split(debuglog.render_curl(request))
    assert argv[0] == "curl"
    assert argv[argv.index("-X") + 1] == "POST"
    assert "https://api.osv.dev/v1/querybatch" in argv
    headers = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert "User-Agent: vulnscan/test" in headers
    assert "Accept: application/json" in headers
    assert any(h.lower().startswith("content-type: application/json") for h in headers)
    body = argv[argv.index("--data-binary") + 1]
    assert json.loads(body) == json.loads(request.content)


def test_render_curl_is_one_line_and_shell_safe():
    request = _request(
        url="https://example.test/path?a=1&b=it's",
        json_body={"text": 'quote \' and $dollar and "double"'},
    )
    command = debuglog.render_curl(request)
    assert "\n" not in command
    argv = shlex.split(command)
    assert "https://example.test/path?a=1&b=it's" in argv
    assert json.loads(argv[argv.index("--data-binary") + 1]) == {
        "text": 'quote \' and $dollar and "double"'
    }


def test_render_curl_get_has_no_body_or_explicit_method_payload():
    request = _request(method="GET", url="https://pypi.org/pypi/requests/json")
    command = debuglog.render_curl(request)
    assert "--data" not in command
    assert "https://pypi.org/pypi/requests/json" in shlex.split(command)


def test_render_curl_replaces_secrets_with_shell_variables():
    request = _request(
        method="GET",
        url="https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
        headers={"Authorization": "Bearer s3cretKEY"},
    )
    command = debuglog.render_curl(request, secrets={"s3cretKEY": "$VULNSCAN_WORDFENCE_API_KEY"})
    assert "s3cretKEY" not in command
    assert '"Authorization: Bearer $VULNSCAN_WORDFENCE_API_KEY"' in command


def test_render_curl_replaces_secrets_inside_the_url():
    request = _request(
        url="https://prod.webhook.office.com/workflows/abc123/triggers?sig=TOPSECRET",
        json_body={"type": "message"},
    )
    command = debuglog.render_curl(
        request,
        secrets={
            "https://prod.webhook.office.com/workflows/abc123/triggers?sig=TOPSECRET": (
                "$VULNSCAN_MSTEAMS_WEBHOOK_URL"
            )
        },
    )
    assert "TOPSECRET" not in command
    assert '"$VULNSCAN_MSTEAMS_WEBHOOK_URL"' in command


def test_render_curl_keeps_other_shell_characters_literal_next_to_a_secret():
    request = _request(
        method="GET",
        url="https://ntfy.test/",
        headers={"Authorization": "Bearer tk_abc", "X-Note": 'has "quotes" and $x'},
    )
    command = debuglog.render_curl(request, secrets={"tk_abc": "$VULNSCAN_NTFY_TOKEN"})
    argv = shlex.split(command)
    assert 'X-Note: has "quotes" and $x' in argv


# --- secrets_from_settings ---------------------------------------------------------------


def test_secrets_from_settings_covers_every_configured_credential(tmp_path: Path):
    settings = load_settings(
        env={
            "VULNSCAN_WORDFENCE_API_KEY": "wf-key",
            "VULNSCAN_NVD_API_KEY": "nvd-key",
            "VULNSCAN_NTFY_TOKEN": "tk_token",
            "VULNSCAN_NTFY_USER": "alice",
            "VULNSCAN_NTFY_PASSWORD": "pw",
            "VULNSCAN_MSTEAMS_WEBHOOK_URL": "https://hook.test/secret-path",
        },
        dotenv_path=tmp_path / "missing.env",
    )
    secrets = debuglog.secrets_from_settings(settings)
    assert secrets["wf-key"] == "$VULNSCAN_WORDFENCE_API_KEY"
    assert secrets["nvd-key"] == "$VULNSCAN_NVD_API_KEY"
    assert secrets["tk_token"] == "$VULNSCAN_NTFY_TOKEN"
    assert secrets["https://hook.test/secret-path"] == "$VULNSCAN_MSTEAMS_WEBHOOK_URL"
    basic = base64.b64encode(b"alice:pw").decode()
    assert "VULNSCAN_NTFY_USER" in secrets[basic]
    assert "VULNSCAN_NTFY_PASSWORD" in secrets[basic]


def test_secrets_from_settings_skips_empty_values(tmp_path: Path):
    settings = load_settings(env={}, dotenv_path=tmp_path / "missing.env")
    assert "" not in debuglog.secrets_from_settings(settings)


# --- configure / levels --------------------------------------------------------------------


def test_level_one_records_each_request_and_its_response(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"code": 3, "message": "invalid query"})

    with _client(handler) as http:
        http.post("https://api.osv.dev/v1/querybatch", json={"queries": []})
    text = log.read_text()
    assert "POST https://api.osv.dev/v1/querybatch" in text
    assert "400" in text
    assert "invalid query" in text
    curl_lines = [line for line in text.splitlines() if line.lstrip().startswith("$ curl ")]
    assert len(curl_lines) == 1
    argv = shlex.split(curl_lines[0].lstrip()[2:])
    assert "https://api.osv.dev/v1/querybatch" in argv


def test_request_and_response_records_share_a_sequence_number(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    with _client(_ok) as http:
        http.get("https://pypi.org/pypi/a/json")
        http.get("https://pypi.org/pypi/b/json")
    numbers = re.findall(r"#(\d+)", log.read_text())
    assert numbers.count(numbers[0]) >= 2
    assert len(set(numbers)) == 2


def test_connection_failures_are_recorded_against_the_request(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with _client(handler) as http, pytest.raises(httpx.ConnectError):
        http.get("https://down.test/")
    text = log.read_text()
    assert "https://down.test/" in text
    assert "boom" in text


def test_level_one_writes_warnings_but_not_control_flow(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    logging.getLogger("vulnscan.scanner").info("flow-marker")
    logging.getLogger("vulnscan.scanner").warning("warn-marker")
    text = log.read_text()
    assert "flow-marker" not in text
    assert "warn-marker" in text


def test_level_two_writes_control_flow_but_not_internals(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(2, log)
    logging.getLogger("vulnscan.scanner").info("flow-marker")
    logging.getLogger("vulnscan.scanner").debug("internal-marker")
    logging.getLogger("httpcore.connection").debug("library-marker")
    text = log.read_text()
    assert "flow-marker" in text
    assert "internal-marker" not in text
    assert "library-marker" not in text


def test_level_two_still_records_http_exchanges(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(2, log)
    with _client(_ok) as http:
        http.get("https://pypi.org/pypi/requests/json")
    assert "https://pypi.org/pypi/requests/json" in log.read_text()


def test_level_three_writes_internals_and_library_records(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(3, log)
    logging.getLogger("vulnscan.scanner").debug("internal-marker")
    logging.getLogger("httpcore.connection").debug("library-marker")
    text = log.read_text()
    assert "internal-marker" in text
    assert "library-marker" in text


def test_level_three_records_uncaught_exceptions_with_traceback(tmp_path: Path, capsys):
    log = tmp_path / "debug.log"
    debuglog.configure(3, log)
    try:
        raise ZeroDivisionError("division by zero")
    except ZeroDivisionError:
        sys.excepthook(*sys.exc_info())
    text = log.read_text()
    assert "ZeroDivisionError" in text
    assert "Traceback" in text
    assert "ZeroDivisionError" in capsys.readouterr().err


def test_lower_levels_leave_the_exception_hook_alone(tmp_path: Path):
    before = sys.excepthook
    debuglog.configure(2, tmp_path / "debug.log")
    assert sys.excepthook is before


def test_log_starts_with_a_banner_naming_version_level_and_command(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(2, log, argv=["vulnscan", "--markdown", "-", "-dd"])
    first = log.read_text().splitlines()[0]
    assert __version__ in first
    assert "2" in first
    assert "--markdown" in log.read_text()


def test_banner_mentions_the_variables_that_replace_secrets(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log, secrets={"k": "$VULNSCAN_WORDFENCE_API_KEY"})
    assert "VULNSCAN_WORDFENCE_API_KEY" in log.read_text()


@pytest.mark.parametrize("level", [0, 4, -1])
def test_configure_rejects_levels_outside_the_range(tmp_path: Path, level):
    with pytest.raises(ValueError):
        debuglog.configure(level, tmp_path / "debug.log")


def test_configure_creates_missing_parent_directories(tmp_path: Path):
    log = tmp_path / "nested" / "dir" / "debug.log"
    debuglog.configure(1, log)
    assert log.is_file()


def test_long_response_bodies_are_truncated(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    big = "x" * 200_000

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=big)

    with _client(handler) as http:
        response = http.get("https://big.test/")
    assert response.text == big  # the hook must not consume the body
    text = log.read_text()
    assert len(text) < len(big)
    assert "truncat" in text.lower()


def test_json_response_bodies_are_pretty_printed(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"results":[{"vulns":[{"id":"GHSA-1"}]}]}')

    with _client(handler) as http:
        http.get("https://api.osv.dev/v1/x")
    assert '"id": "GHSA-1"' in log.read_text()


def test_secrets_given_to_configure_are_hidden_in_logged_requests(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log, secrets={"tk_secret": "$VULNSCAN_NTFY_TOKEN"})
    with _client(_ok, headers={"Authorization": "Bearer tk_secret"}) as http:
        http.post("https://ntfy.test/", json={"topic": "t"})
    text = log.read_text()
    assert "tk_secret" not in text
    assert "$VULNSCAN_NTFY_TOKEN" in text


def test_hooks_are_inert_until_configured(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert debuglog.is_active() is False
    with _client(_ok) as http:
        assert http.get("https://pypi.org/pypi/requests/json").status_code == 200
    assert not list(tmp_path.iterdir())


def test_reset_stops_logging(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    assert debuglog.is_active() is True
    debuglog.reset()
    assert debuglog.is_active() is False
    with _client(_ok) as http:
        http.get("https://after.test/")
    assert "after.test" not in log.read_text()


def test_configure_twice_replaces_the_previous_log(tmp_path: Path):
    first, second = tmp_path / "one.log", tmp_path / "two.log"
    debuglog.configure(1, first)
    debuglog.configure(1, second)
    with _client(_ok) as http:
        http.get("https://only-second.test/")
    assert "only-second" not in first.read_text()
    assert "only-second" in second.read_text()


# --- every client goes through the debug log ---------------------------------------------


def _dep(name="requests", version="2.30.0", ecosystem=PYPI) -> Dependency:
    return Dependency(name, ecosystem, f"=={version}", version, "pinned", "requirements.txt")


def test_osv_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"vulns": []}]})

    OSVClient("https://osv.test", transport=httpx.MockTransport(handler)).query_batch([_dep()])
    text = log.read_text()
    assert "https://osv.test/v1/querybatch" in text
    assert "curl " in text


def test_registry_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"info": {"version": "2.31.0"}, "releases": {"2.31.0": []}})

    RegistryClient(transport=httpx.MockTransport(handler)).available_versions(_dep())
    assert "pypi.org" in log.read_text()


def test_wordfence_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log, secrets={"KEY": "$VULNSCAN_WORDFENCE_API_KEY"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    client = WordfenceClient(
        api_key="KEY",
        base_url="https://wf.test/api/intelligence/v3",
        cache_path=tmp_path / "cache" / "wordfence.json",
        transport=httpx.MockTransport(handler),
    )
    client.find_vulnerabilities(
        [
            Dependency(
                "wp-plugin/x",
                "WordPress",
                "1.0",
                "1.0",
                "lock",
                "composer.json",
                kind="plugin",
                slug="x",
            )
        ]
    )
    text = log.read_text()
    assert "https://wf.test/api/intelligence/v3" in text
    assert "Bearer KEY" not in text
    assert "$VULNSCAN_WORDFENCE_API_KEY" in text


def test_nvd_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    client = NVDClient(
        base_url="https://nvd.test/cves",
        cache_dir=tmp_path / "cache",
        transport=httpx.MockTransport(handler),
        sleep=lambda seconds: None,
    )
    php = Dependency("php", "Docker", "8.2.19", "8.2.19", "pinned", "Dockerfile", kind="image")
    client.find_vulnerabilities([php])
    assert "https://nvd.test/cves" in log.read_text()


def test_ntfy_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    NtfyClient("https://ntfy.test", "topic", transport=httpx.MockTransport(_ok)).publish(
        NtfyMessage(title="t", body="b", priority=3, tags=(), click=None, guids=())
    )
    assert "https://ntfy.test/" in log.read_text()


def test_msteams_requests_are_logged(tmp_path: Path):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    TeamsClient("https://hook.test/x", transport=httpx.MockTransport(_ok)).send_test("proj")
    assert "https://hook.test/x" in log.read_text()


# --- activity reporting --------------------------------------------------------------------


class _Chunks(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


@pytest.fixture
def transfers():
    from vulnscan import activity

    activity.reset()
    seen: list = []
    activity.subscribe(seen.append)
    yield seen
    activity.reset()


def _chunked(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        stream=_Chunks([b"a" * 100, b"b" * 100, b"c" * 100]),
        headers={"content-length": "300", "content-type": "text/plain"},
    )


def test_client_reports_start_headers_progress_and_finish_without_a_debug_log(transfers):
    assert not debuglog.is_active()
    with _client(_chunked) as http:
        response = http.get("https://pypi.org/pypi/requests/json")
    assert response.content == b"a" * 100 + b"b" * 100 + b"c" * 100
    first, last = transfers[0], transfers[-1]
    assert first.method == "GET"
    assert first.url == "https://pypi.org/pypi/requests/json"
    assert first.status is None and first.received == 0 and not first.done
    assert any(t.status == 200 and t.total == 300 for t in transfers)
    received = [t.received for t in transfers]
    assert received == sorted(received)
    assert {100, 200, 300} <= set(received)
    assert last.done and not last.failed
    assert last.status == 200 and last.received == 300 and last.total == 300
    assert len({t.id for t in transfers}) == 1


def test_client_reports_an_unknown_size_when_there_is_no_content_length(transfers):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_Chunks([b"xyz"]), headers={"content-type": "text/plain"})

    with _client(handler) as http:
        http.get("https://example.test/")
    assert transfers[-1].total is None
    assert transfers[-1].received == 3


def test_client_reports_transport_failures(transfers):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with _client(handler) as http, pytest.raises(httpx.ConnectError):
        http.get("https://down.test/")
    last = transfers[-1]
    assert last.done and last.failed
    assert "boom" in last.error
    assert last.status is None


def test_client_reports_error_statuses_as_finished_not_failed(transfers):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"message": "bad"})

    with _client(handler) as http:
        http.post("https://api.osv.dev/v1/querybatch", json={})
    assert transfers[-1].status == 400
    assert transfers[-1].done and not transfers[-1].failed


def test_streaming_callers_finish_the_transfer_when_they_read_the_body(transfers):
    with _client(_chunked) as http:
        response = http.send(http.build_request("GET", "https://pypi.org/x"), stream=True)
        assert not transfers[-1].done
        response.read()
        response.close()
    assert transfers[-1].done and transfers[-1].received == 300


def test_each_request_gets_its_own_transfer(transfers):
    with _client(_ok) as http:
        http.get("https://a.test/")
        http.get("https://b.test/")
    ids = {t.id for t in transfers}
    assert len(ids) == 2
    assert [t.url for t in transfers if t.done] == ["https://a.test/", "https://b.test/"]


def test_a_failing_observer_does_not_break_the_request(transfers):
    from vulnscan import activity

    def bad(transfer):
        raise RuntimeError("observer broke")

    activity.subscribe(bad)
    with _client(_ok) as http:
        assert http.get("https://a.test/").status_code == 200


def test_activity_and_debug_log_work_together(tmp_path: Path, transfers):
    log = tmp_path / "debug.log"
    debuglog.configure(1, log)
    with _client(_chunked) as http:
        http.get("https://pypi.org/pypi/requests/json")
    assert transfers[-1].done
    assert "https://pypi.org/pypi/requests/json" in log.read_text()
