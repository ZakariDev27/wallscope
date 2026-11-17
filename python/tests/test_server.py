import http.cookiejar
import json
import threading
import urllib.error
import urllib.request

import pytest

from wallscope.engine import Engine
from wallscope.server import create_server

PASSWORD = "correct-horse-battery"


class Client:
    def __init__(self, base: str):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method: str, path: str, body: dict | None = None, headers: dict | None = None):
        request_headers = {"Content-Type": "application/json", "X-WallScope": "1"} if method == "POST" else {}
        request_headers.update(headers or {})
        data = json.dumps(body or {}).encode() if method == "POST" else None
        request = urllib.request.Request(self.base + path, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read()
                kind = response.headers.get("Content-Type", "")
                return response.status, (json.loads(raw) if "json" in kind and not response.headers.get("Content-Disposition") else raw), response.headers
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}"), error.headers


class FakeEngine(Engine):
    def __init__(self, report: dict):
        super().__init__(["fake"], "fake engine")
        self.report = report
        self.requests = []

    def run(self, request, timeout_seconds: int = 600):
        request.validate()
        self.requests.append(request)
        return self.report


@pytest.fixture
def server(tmp_path, sample):
    engine = FakeEngine(sample)
    instance = create_server(port=0, home=tmp_path, engine=engine)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield Client(f"http://127.0.0.1:{instance.server_address[1]}"), engine, tmp_path
    instance.shutdown()
    instance.server_close()


def signed_in(client: Client) -> Client:
    assert client.call("POST", "/api/setup", {"username": "zakari", "password": PASSWORD})[0] == 200
    return client


def test_static_page_and_security_headers(server):
    client, _, _ = server
    status, body, headers = client.call("GET", "/")
    assert status == 200 and b"WallScope" in body and b"By ZaKari Perry" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert client.call("GET", "/static/app.js")[0] == 200
    assert client.call("GET", "/static/..%2fserver.py")[0] == 404


def test_api_requires_a_session(server):
    client, _, _ = server
    assert client.call("GET", "/api/session")[1] == {"setupRequired": True, "authenticated": False, "user": None}
    for method, path in (("GET", "/api/status"), ("GET", "/api/reports"), ("POST", "/api/scan"), ("POST", "/api/chat"), ("POST", "/api/sample")):
        assert client.call(method, path)[0] == 401


def test_setup_login_logout_cycle(server):
    client, _, home = server
    assert client.call("POST", "/api/setup", {"username": "zakari", "password": "short"})[0] == 400
    assert client.call("POST", "/api/setup", {"username": "bad name!", "password": PASSWORD})[0] == 400
    status, _, headers = client.call("POST", "/api/setup", {"username": "zakari", "password": PASSWORD})
    assert status == 200
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Strict" in headers["Set-Cookie"]
    assert client.call("GET", "/api/session")[1]["user"] == "zakari"
    # Setup only works once.
    assert client.call("POST", "/api/setup", {"username": "other", "password": PASSWORD})[0] == 409
    # The password is not stored in the clear.
    stored = (home / "users.json").read_text(encoding="utf-8")
    assert PASSWORD not in stored and "salt" in stored

    assert client.call("POST", "/api/logout")[0] == 200
    assert client.call("GET", "/api/status")[0] == 401
    assert client.call("POST", "/api/login", {"username": "zakari", "password": "wrong-password"})[0] == 401
    assert client.call("POST", "/api/login", {"username": "ZAKARI", "password": PASSWORD})[0] == 200
    assert client.call("GET", "/api/status")[1]["engine"] == "fake engine"


def test_login_is_rate_limited(server):
    client, _, _ = server
    signed_in(client).call("POST", "/api/logout")
    for _ in range(5):
        assert client.call("POST", "/api/login", {"username": "zakari", "password": "wrong-password"})[0] == 401
    assert client.call("POST", "/api/login", {"username": "zakari", "password": PASSWORD})[0] == 429


def test_cross_site_and_rebinding_requests_are_refused(server):
    client, _, _ = server
    signed_in(client)
    # A cross-site form post cannot add the custom header.
    assert client.call("POST", "/api/sample", headers={"X-WallScope": ""})[0] == 403
    # A DNS-rebinding page would arrive with its own Host header.
    assert client.call("GET", "/api/status", headers={"Host": "evil.example"})[0] == 403


def test_scan_saves_report_and_lists_history(server):
    client, engine, _ = server
    signed_in(client)
    status, body, _ = client.call("POST", "/api/scan", {"local": True, "targets": "127.0.0.1, localhost", "ports": "22,80"})
    assert status == 200
    assert body["risk"]["grade"] == "F" and body["label"] == "local audit, 127.0.0.1, localhost"
    assert engine.requests[0].targets == ("127.0.0.1", "localhost")

    listing = client.call("GET", "/api/reports")[1]
    assert [item["id"] for item in listing] == [body["id"]]
    assert client.call("GET", f"/api/reports/{body['id']}")[1]["report"]["host"] == "SAMPLE-WORKSTATION"
    assert client.call("GET", "/api/reports/..%2f..%2fusers")[0] == 400
    assert client.call("GET", "/api/reports/20260101T000000Z-abcdef")[0] == 404


def test_scan_rejects_bad_input_before_reaching_the_engine(server):
    client, engine, _ = server
    signed_in(client)
    status, body, _ = client.call("POST", "/api/scan", {"targets": ["host; whoami"]})
    assert status == 400 and "not a valid host" in body["error"]
    assert client.call("POST", "/api/scan", {})[0] == 400
    assert engine.requests == []


def test_export_diff_and_chat(server):
    client, _, _ = server
    signed_in(client)
    first = client.call("POST", "/api/sample")[1]["id"]
    second = client.call("POST", "/api/sample")[1]["id"]

    for fmt, marker in (("html", b"<!DOCTYPE html>"), ("md", b"# WallScope report"), ("sarif", b'"version": "2.1.0"'), ("json", b'"findings"')):
        status, raw, headers = client.call("GET", f"/api/reports/{first}/export?format={fmt}")
        assert status == 200 and marker in raw
        assert "attachment" in headers["Content-Disposition"]
    assert client.call("GET", f"/api/reports/{first}/export?format=exe")[0] == 400

    assert client.call("POST", "/api/diff", {"base": first, "head": second})[1]["changed"] is False
    reply = client.call("POST", "/api/chat", {"message": "What should I fix first?", "reportId": first})[1]
    assert "[CRITICAL]" in reply["text"] and reply["mood"] == "alert" and reply["suggestions"]
