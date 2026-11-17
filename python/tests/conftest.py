import json
from importlib import resources

import pytest


@pytest.fixture
def sample() -> dict:
    return json.loads(resources.files("wallscope").joinpath("data", "sample-report.json").read_text("utf-8"))


@pytest.fixture
def clean() -> dict:
    return {
        "host": "h",
        "os": "linux",
        "finishedUtc": "2026-01-01T00:00:00+00:00",
        "localAudit": {"platform": "linux", "firewallActive": True, "elevated": True, "backends": []},
        "networkProbes": [],
        "wafResults": [],
        "findings": [],
    }
