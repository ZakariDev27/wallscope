"""Locates and runs the C# detection engine, returning its JSON report."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
_CLI_PROJECT = REPO_ROOT / "src" / "FirewallDetector.Cli"

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$")
_PORTS_RE = re.compile(r"^(top|\d{1,5}(-\d{1,5})?)(,(top|\d{1,5}(-\d{1,5})?))*$", re.IGNORECASE)


class EngineError(RuntimeError):
    """The engine is missing, rejected the request, or failed."""


@dataclass(frozen=True)
class ScanRequest:
    local: bool = False
    targets: tuple[str, ...] = ()
    ports: str = "top"
    urls: tuple[str, ...] = ()
    passive: bool = False
    insecure: bool = False
    authorized: bool = False
    timeout_ms: int = 1500

    def validate(self) -> None:
        """Reject anything that is not a plain host, port spec or http(s) URL before it reaches a process."""
        if not (self.local or self.targets or self.urls):
            raise EngineError("Choose at least one thing to scan.")
        for target in self.targets:
            if not is_valid_host(target):
                raise EngineError(f"'{target}' is not a valid host name or IP address.")
        for url in self.urls:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise EngineError(f"'{url}' is not a valid http(s) URL.")
        if not _PORTS_RE.match(self.ports.replace(" ", "")):
            raise EngineError(f"'{self.ports}' is not a valid port list. Try 'top' or '22,80,443'.")
        if not 100 <= self.timeout_ms <= 60_000:
            raise EngineError("Timeout must be between 100 and 60000 ms.")

    def to_args(self) -> list[str]:
        args = ["scan", "--format", "json", "--timeout", str(self.timeout_ms)]
        if self.local:
            args.append("--local")
        if self.targets:
            args += ["--targets", ",".join(self.targets), "--ports", self.ports.replace(" ", "")]
        if self.urls:
            args += ["--urls", ",".join(self.urls)]
        if self.passive:
            args.append("--passive")
        if self.insecure:
            args.append("--insecure")
        if self.authorized:
            args.append("--authorized")
        return args


def is_valid_host(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOST_RE.match(value))


@dataclass
class Engine:
    """A resolved way of invoking the engine, e.g. ['dotnet', '/path/wallscope.dll']."""

    command: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def locate(cls) -> "Engine | None":
        override = os.environ.get("WALLSCOPE_ENGINE")
        if override:
            path = Path(override)
            if path.suffix == ".dll":
                return cls(["dotnet", str(path)], f"WALLSCOPE_ENGINE ({path})")
            return cls([str(path)], f"WALLSCOPE_ENGINE ({path})")

        dotnet = shutil.which("dotnet")
        for config in ("Release", "Debug"):
            dll = _CLI_PROJECT / "bin" / config / "net8.0" / "wallscope.dll"
            if dll.exists() and dotnet:
                return cls([dotnet, str(dll)], f"local {config} build")

        on_path = shutil.which("wallscope")
        if on_path:
            return cls([on_path], "wallscope on PATH")

        if dotnet and (_CLI_PROJECT / "FirewallDetector.Cli.csproj").exists():
            return cls(
                [dotnet, "run", "--project", str(_CLI_PROJECT), "-c", "Release", "--"],
                "dotnet run (builds on first use)",
            )
        return None

    def run(self, request: ScanRequest, timeout_seconds: int = 600) -> dict:
        request.validate()
        try:
            completed = subprocess.run(  # noqa: S603 - arguments are validated and passed as a list, no shell
                [*self.command, *request.to_args()],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise EngineError(f"Engine could not be started: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise EngineError("The scan took too long and was stopped.") from exc

        if completed.returncode not in (0, 2):
            message = (completed.stderr or completed.stdout).strip().splitlines()
            raise EngineError(message[0] if message else f"Engine exited with code {completed.returncode}.")

        start = completed.stdout.find("{")
        if start < 0:
            raise EngineError("Engine produced no report.")
        try:
            return json.loads(completed.stdout[start:])
        except json.JSONDecodeError as exc:
            raise EngineError(f"Engine report was not valid JSON: {exc}") from exc


def load_report(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict) or "findings" not in report:
        raise EngineError(f"{path} is not a WallScope report.")
    return report
