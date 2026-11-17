"""Local WallScope dashboard: static front end plus a small JSON API.

Security model: the server binds to loopback by default, every API call needs a signed-in session
(password stored as a salted PBKDF2 hash), state-changing calls must carry a custom header that a
cross-site form cannot send, and the Host header is checked to stop DNS-rebinding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from wallscope import __version__, assistant, report as render
from wallscope.analysis import diff_reports, score_report
from wallscope.engine import Engine, EngineError, ScanRequest

SESSION_COOKIE = "wallscope_session"
SESSION_TTL = 8 * 60 * 60
MAX_BODY = 256 * 1024
PBKDF2_ROUNDS = 310_000
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
_REPORT_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class UserStore:
    """Operator accounts in a JSON file. Passwords are never stored, only salted PBKDF2-SHA256 hashes."""

    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()

    def _read(self) -> dict:
        if not self._path.exists():
            return {}
        with open(self._path, encoding="utf-8") as handle:
            return json.load(handle)

    def has_users(self) -> bool:
        with self._lock:
            return bool(self._read())

    @staticmethod
    def _hash(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS).hex()

    def create(self, username: str, password: str) -> None:
        if not _USERNAME_RE.match(username):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Username must be 3-32 letters, numbers, dots, dashes or underscores.")
        if len(password) < 10:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Password must be at least 10 characters.")
        with self._lock:
            users = self._read()
            if username.lower() in users:
                raise ApiError(HTTPStatus.CONFLICT, "That username is taken.")
            salt = secrets.token_bytes(16)
            users[username.lower()] = {"name": username, "salt": salt.hex(), "hash": self._hash(password, salt)}
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp = self._path.with_suffix(".tmp")
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(users, handle)
            os.chmod(temp, 0o600)
            os.replace(temp, self._path)

    def verify(self, username: str, password: str) -> str | None:
        with self._lock:
            record = self._read().get(username.lower())
        # Hash even for unknown users so response time does not reveal which names exist.
        salt = bytes.fromhex(record["salt"]) if record else b"\0" * 16
        candidate = self._hash(password, salt)
        if record and hmac.compare_digest(candidate, record["hash"]):
            return record["name"]
        return None


class ReportStore:
    def __init__(self, directory: Path):
        self._dir = directory

    def save(self, report: dict, label: str) -> str:
        self._dir.mkdir(parents=True, exist_ok=True)
        report_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
        with open(self._dir / f"{report_id}.json", "w", encoding="utf-8") as handle:
            json.dump({"label": label, "report": report}, handle)
        return report_id

    def load(self, report_id: str) -> dict:
        if not _REPORT_ID_RE.match(report_id):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid report id.")
        path = self._dir / f"{report_id}.json"
        if not path.exists():
            raise ApiError(HTTPStatus.NOT_FOUND, "Report not found.")
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def list(self) -> list[dict]:
        if not self._dir.exists():
            return []
        items = []
        for path in sorted(self._dir.glob("*.json"), reverse=True)[:100]:
            try:
                with open(path, encoding="utf-8") as handle:
                    stored = json.load(handle)
                risk = score_report(stored["report"])
                items.append(
                    {
                        "id": path.stem,
                        "label": stored.get("label", ""),
                        "host": stored["report"].get("host"),
                        "finishedUtc": stored["report"].get("finishedUtc"),
                        "score": risk.score,
                        "grade": risk.grade,
                        "findings": len(stored["report"].get("findings", [])),
                    }
                )
            except (OSError, KeyError, json.JSONDecodeError):
                continue
        return items


class App:
    """Everything the request handler needs; one instance per server."""

    def __init__(self, home: Path, engine: Engine | None):
        self.users = UserStore(home / "users.json")
        self.reports = ReportStore(home / "reports")
        self.engine = engine
        self.sessions: dict[str, tuple[str, float]] = {}
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()

    # sessions

    def open_session(self, user: str) -> str:
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = (user, time.time() + SESSION_TTL)
        return token

    def session_user(self, token: str | None) -> str | None:
        if not token:
            return None
        with self.lock:
            entry = self.sessions.get(token)
            if not entry:
                return None
            if entry[1] < time.time():
                del self.sessions[token]
                return None
            return entry[0]

    def close_session(self, token: str | None) -> None:
        with self.lock:
            self.sessions.pop(token or "", None)

    def throttle(self, client: str) -> None:
        """At most 5 failed sign-ins per client per 5 minutes."""
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(client, []) if now - t < 300]
            self.failures[client] = recent
            if len(recent) >= 5:
                raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many attempts. Wait a few minutes and try again.")

    def record_failure(self, client: str) -> None:
        with self.lock:
            self.failures.setdefault(client, []).append(time.time())


def _static(name: str) -> tuple[bytes, str] | None:
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        return None
    resource = resources.files("wallscope").joinpath("web", name)
    if not resource.is_file():
        return None
    content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
    return resource.read_bytes(), content_type


def sample_report() -> dict:
    return json.loads(resources.files("wallscope").joinpath("data", "sample-report.json").read_text("utf-8"))


def make_handler(app: App, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"WallScope/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - signature fixed by base class
            return

        # ----- plumbing -----

        def _send(self, status: HTTPStatus, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: dict | list, status: HTTPStatus = HTTPStatus.OK, extra: dict[str, str] | None = None) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8", extra)

        def _token(self) -> str | None:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return cookie[SESSION_COOKIE].value if SESSION_COOKIE in cookie else None

        def _user(self) -> str:
            user = app.session_user(self._token())
            if not user:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "Sign in to continue.")
            return user

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large.")
            if self.headers.get("X-WallScope") != "1":
                raise ApiError(HTTPStatus.FORBIDDEN, "Missing request header.")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError as exc:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Body must be JSON.") from exc
            if not isinstance(data, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "Body must be a JSON object.")
            return data

        def _cookie(self, token: str, max_age: int) -> dict[str, str]:
            return {"Set-Cookie": f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"}

        def _dispatch(self, method: str) -> None:
            try:
                if self.headers.get("Host", "").lower() not in allowed_hosts:
                    raise ApiError(HTTPStatus.FORBIDDEN, "Unexpected Host header.")
                url = urlsplit(self.path)
                if method == "GET":
                    self._get(url.path, parse_qs(url.query))
                else:
                    self._post(url.path)
            except ApiError as error:
                self._json({"error": error.message}, error.status)
            except EngineError as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self) -> None:  # noqa: N802 - name fixed by base class
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        # ----- routes -----

        def _get(self, path: str, query: dict[str, list[str]]) -> None:
            if path in ("/", "/index.html"):
                body, content_type = _static("index.html") or (b"", "text/html")
                return self._send(HTTPStatus.OK, body, content_type + "; charset=utf-8")
            if path.startswith("/static/"):
                asset = _static(path.removeprefix("/static/"))
                if not asset:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Not found.")
                charset = "; charset=utf-8" if asset[1].startswith(("text/", "application/javascript")) else ""
                return self._send(HTTPStatus.OK, asset[0], asset[1] + charset)
            if path == "/api/session":
                user = app.session_user(self._token())
                return self._json({"setupRequired": not app.users.has_users(), "authenticated": bool(user), "user": user})

            self._user()
            if path == "/api/status":
                return self._json(
                    {
                        "version": __version__,
                        "engine": app.engine.description if app.engine else None,
                        "assistant": assistant.ai_mode(),
                    }
                )
            if path == "/api/reports":
                return self._json(app.reports.list())
            match = re.fullmatch(r"/api/reports/([^/]+)(/export)?", path)
            if match:
                stored = app.reports.load(match.group(1))
                if not match.group(2):
                    return self._json(
                        {"id": match.group(1), "label": stored.get("label", ""), "report": stored["report"], "risk": score_report(stored["report"]).to_dict()}
                    )
                return self._export(match.group(1), stored["report"], (query.get("format") or ["html"])[0])
            raise ApiError(HTTPStatus.NOT_FOUND, "Not found.")

        def _export(self, report_id: str, report: dict, fmt: str) -> None:
            if fmt == "html":
                body, content_type, ext = render.to_html(report).encode(), "text/html; charset=utf-8", "html"
            elif fmt == "md":
                body, content_type, ext = render.to_markdown(report).encode(), "text/markdown; charset=utf-8", "md"
            elif fmt == "sarif":
                body, content_type, ext = json.dumps(render.to_sarif(report), indent=2).encode(), "application/json", "sarif"
            elif fmt == "json":
                body, content_type, ext = json.dumps(report, indent=2).encode(), "application/json", "json"
            else:
                raise ApiError(HTTPStatus.BAD_REQUEST, "Format must be html, md, sarif or json.")
            self._send(HTTPStatus.OK, body, content_type, {"Content-Disposition": f'attachment; filename="wallscope-{report_id}.{ext}"'})

        def _post(self, path: str) -> None:
            data = self._body()
            client = self.client_address[0]

            if path == "/api/setup":
                if app.users.has_users():
                    raise ApiError(HTTPStatus.CONFLICT, "Setup is already complete. Sign in instead.")
                app.users.create(str(data.get("username", "")), str(data.get("password", "")))
                token = app.open_session(str(data["username"]))
                return self._json({"user": data["username"]}, extra=self._cookie(token, SESSION_TTL))

            if path == "/api/login":
                app.throttle(client)
                user = app.users.verify(str(data.get("username", "")), str(data.get("password", "")))
                if not user:
                    app.record_failure(client)
                    raise ApiError(HTTPStatus.UNAUTHORIZED, "Wrong username or password.")
                return self._json({"user": user}, extra=self._cookie(app.open_session(user), SESSION_TTL))

            if path == "/api/logout":
                app.close_session(self._token())
                return self._json({"ok": True}, extra=self._cookie("", 0))

            self._user()

            if path == "/api/scan":
                return self._scan(data)
            if path == "/api/sample":
                report = sample_report()
                report_id = app.reports.save(report, "Sample data")
                return self._json({"id": report_id, "label": "Sample data", "report": report, "risk": score_report(report).to_dict()})
            if path == "/api/diff":
                base = app.reports.load(str(data.get("base", "")))["report"]
                head = app.reports.load(str(data.get("head", "")))["report"]
                return self._json(diff_reports(base, head).to_dict())
            if path == "/api/chat":
                report = None
                if data.get("reportId"):
                    report = app.reports.load(str(data["reportId"]))["report"]
                history = data.get("history") if isinstance(data.get("history"), list) else []
                return self._json(assistant.answer(str(data.get("message", "")), report, history).to_dict())
            raise ApiError(HTTPStatus.NOT_FOUND, "Not found.")

        def _scan(self, data: dict) -> None:
            if not app.engine:
                raise ApiError(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "The scan engine is not built yet. Run 'dotnet build -c Release' in the project folder, then restart.",
                )

            def items(key: str) -> tuple[str, ...]:
                value = data.get(key) or []
                if isinstance(value, str):
                    value = value.replace("\n", ",").split(",")
                return tuple(str(v).strip() for v in value if str(v).strip())[:32]

            request = ScanRequest(
                local=bool(data.get("local")),
                targets=items("targets"),
                ports=str(data.get("ports") or "top"),
                urls=items("urls"),
                passive=bool(data.get("passive")),
                insecure=bool(data.get("insecure")),
                authorized=bool(data.get("authorized")),
            )
            if not app.scan_lock.acquire(blocking=False):
                raise ApiError(HTTPStatus.CONFLICT, "A scan is already running. Wait for it to finish.")
            try:
                report = app.engine.run(request)
            finally:
                app.scan_lock.release()

            parts = (["local audit"] if request.local else []) + list(request.targets) + list(request.urls)
            label = ", ".join(parts)[:120]
            report_id = app.reports.save(report, label)
            self._json({"id": report_id, "label": label, "report": report, "risk": score_report(report).to_dict()})

    return Handler


def default_home() -> Path:
    return Path(os.environ.get("WALLSCOPE_HOME") or Path.home() / ".wallscope")


def create_server(host: str = "127.0.0.1", port: int = 8787, home: Path | None = None, engine: Engine | None = None) -> ThreadingHTTPServer:
    app = App(home or default_home(), engine if engine is not None else Engine.locate())
    server = ThreadingHTTPServer((host, port), make_handler(app, set()))
    actual_port = server.server_address[1]
    hosts = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}", f"[::1]:{actual_port}"}
    if host not in ("127.0.0.1", "localhost", "::1"):
        hosts.add(f"{host}:{actual_port}")
    server.RequestHandlerClass = make_handler(app, hosts)
    server.daemon_threads = True
    server.app = app  # type: ignore[attr-defined]
    return server


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = create_server(host, port)
    app: App = server.app  # type: ignore[attr-defined]
    url = f"http://{'127.0.0.1' if host in ('127.0.0.1', '0.0.0.0') else host}:{server.server_address[1]}"
    print(f"WallScope dashboard  ->  {url}")
    print(f"By ZaKari Perry  |  engine: {app.engine.description if app.engine else 'NOT FOUND (build it to run scans)'}  |  assistant: {assistant.ai_mode()}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: listening beyond loopback without TLS. Put this behind a trusted network or reverse proxy.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
