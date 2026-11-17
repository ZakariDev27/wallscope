import json
import sys

import pytest

from wallscope import assistant, report
from wallscope.cli import main
from wallscope.engine import Engine, EngineError, ScanRequest


@pytest.mark.parametrize(
    "request_",
    [
        ScanRequest(),
        ScanRequest(targets=("bad host; rm -rf /",)),
        ScanRequest(targets=("--output",)),
        ScanRequest(urls=("ftp://example.com",)),
        ScanRequest(urls=("javascript:alert(1)",)),
        ScanRequest(targets=("127.0.0.1",), ports="22;id"),
        ScanRequest(local=True, timeout_ms=5),
    ],
)
def test_scan_request_rejects_unsafe_input(request_):
    with pytest.raises(EngineError):
        request_.validate()


def test_scan_request_builds_engine_arguments():
    request = ScanRequest(local=True, targets=("10.0.0.5", "db.internal"), ports="22, 443", urls=("https://a.example/",), passive=True, authorized=True)
    request.validate()
    args = request.to_args()
    assert args[:3] == ["scan", "--format", "json"]
    assert args[args.index("--targets") + 1] == "10.0.0.5,db.internal"
    assert args[args.index("--ports") + 1] == "22,443"
    assert {"--local", "--passive", "--authorized"} <= set(args)
    assert "--insecure" not in args


def _fake_engine(tmp_path, body: str) -> Engine:
    script = tmp_path / "fake_engine.py"
    script.write_text(body, encoding="utf-8")
    return Engine([sys.executable, str(script)], "fake")


def test_engine_parses_report_and_accepts_findings_exit_code(tmp_path):
    engine = _fake_engine(tmp_path, 'import sys, json\nprint(json.dumps({"findings": [], "args": sys.argv[1:]}))\nsys.exit(2)\n')
    result = engine.run(ScanRequest(local=True))
    assert result["findings"] == []
    assert "--local" in result["args"]


def test_engine_surfaces_first_line_of_failure(tmp_path):
    engine = _fake_engine(tmp_path, 'import sys\nprint("error: nope", file=sys.stderr)\nsys.exit(1)\n')
    with pytest.raises(EngineError, match="error: nope"):
        engine.run(ScanRequest(local=True))


def test_markdown_and_html_cover_every_section(sample):
    markdown = report.to_markdown(sample)
    for text in ("# WallScope report", "## Local firewall", "## Network probes", "## Web application firewalls", "## Findings (9)", "Cloudflare (100%)"):
        assert text in markdown
    html = report.to_html(sample)
    assert "By ZaKari Perry" in html
    assert html.count("<article>") == 9


def test_html_escapes_untrusted_report_content(clean):
    clean["findings"] = [{"id": "WAF-004", "severity": "low", "title": "<script>alert(1)</script>", "detail": "x", "target": "<img src=x>"}]
    html = report.to_html(clean)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x>" not in html


def test_sarif_structure(sample):
    sarif = report.to_sarif(sample)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == 9
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {f["id"] for f in sample["findings"]}
    assert run["results"][0]["level"] == "error"


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("Summarize my scan", "Risk score 100/100"),
        ("What should I fix first?", "1. [CRITICAL]"),
        ("Which ports are open?", "3306 (mysql)"),
        ("Explain LOCAL-004", "LOCAL-004 appears 1 time"),
        ("explain net-003", "NET-003 appears 3 time"),
        ("tell me about the waf", "Cloudflare at 100% confidence"),
        ("how is the local firewall", "profile Public: OFF"),
        ("Explain my risk score", "1 critical, 3 high"),
        ("What is a WAF?", "web application firewall"),
    ],
)
def test_builtin_assistant_answers_from_the_report(sample, monkeypatch, question, expected):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    reply = assistant.answer(question, sample)
    assert expected in reply.text
    assert reply.source == "built-in"


def test_assistant_without_report_and_mood(sample, clean, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert "don't have a scan" in assistant.answer("summarize", None).text
    assert assistant.answer("summarize", sample).mood == "alert"
    assert assistant.answer("summarize", clean).mood == "happy"
    assert "not in this scan" in assistant.answer("Explain WAF-005", clean).text


def test_assistant_falls_back_when_the_api_is_unreachable(sample, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def boom(*_args, **_kwargs):
        raise TimeoutError("no network")

    monkeypatch.setattr(assistant.urllib.request, "urlopen", boom)
    reply = assistant.answer("Summarize my scan", sample)
    assert reply.source == "built-in"
    assert "Risk score" in reply.text


def test_assistant_uses_claude_reply_and_marks_report_untrusted(sample, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({"content": [{"type": "text", "text": "Close RDP first."}]}).encode()

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["key"] = request.get_header("X-api-key")
        return FakeResponse()

    monkeypatch.setattr(assistant.urllib.request, "urlopen", fake_urlopen)
    reply = assistant.answer("What first?", sample, [{"role": "assistant", "content": "Hi"}, {"role": "user", "content": "Hello"}])

    assert (reply.text, reply.source) == ("Close RDP first.", "claude")
    assert captured["key"] == "test-key"
    assert "untrusted data" in captured["body"]["system"]
    assert captured["body"]["messages"][0]["role"] == "user"
    assert captured["body"]["messages"][-1]["content"] == "What first?"


def test_cli_report_score_check_and_diff(tmp_path, sample, clean, capsys):
    sample_path, clean_path = tmp_path / "sample.json", tmp_path / "clean.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")
    clean_path.write_text(json.dumps(clean), encoding="utf-8")
    policy = tmp_path / "policy.toml"
    policy.write_text('[policy]\nfail_on = "high"\n', encoding="utf-8")

    assert main(["report", str(sample_path), "--format", "html", "--out", str(tmp_path / "r.html")]) == 0
    assert "WallScope report" in (tmp_path / "r.html").read_text(encoding="utf-8")
    assert main(["score", str(sample_path)]) == 0
    assert main(["check", str(sample_path), "--policy", str(policy)]) == 2
    assert main(["check", str(clean_path), "--policy", str(policy)]) == 0
    assert main(["diff", str(clean_path), str(sample_path), "--fail-on-change"]) == 3
    assert main(["diff", str(clean_path), str(clean_path), "--fail-on-change"]) == 0
    assert main(["report", str(tmp_path / "missing.json")]) == 1
    assert "+ NEW" in capsys.readouterr().out
