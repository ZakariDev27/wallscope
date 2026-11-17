"""wallscope-hub: command-line front end for the platform layer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wallscope import __version__, report as render
from wallscope.analysis import Policy, check_policy, diff_reports, score_report
from wallscope.engine import Engine, EngineError, ScanRequest, load_report


def _split(value: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (value or "").split(",") if part.strip())


def _cmd_scan(args: argparse.Namespace) -> int:
    engine = Engine.locate()
    if engine is None:
        raise EngineError("Scan engine not found. Build it with 'dotnet build -c Release' or set WALLSCOPE_ENGINE.")
    report = engine.run(
        ScanRequest(
            local=args.local,
            targets=_split(args.targets),
            ports=args.ports,
            urls=_split(args.urls),
            passive=args.passive,
            insecure=args.insecure,
            authorized=args.authorized,
        )
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    risk = score_report(report)
    print(f"Report saved to {out}")
    print(f"Risk {risk.score}/100, grade {risk.grade} ({risk.posture}); {len(report.get('findings', []))} finding(s).")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    report = load_report(args.report)
    if args.format == "html":
        text = render.to_html(report)
    elif args.format == "sarif":
        text = json.dumps(render.to_sarif(report), indent=2)
    else:
        text = render.to_markdown(report)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(text)
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    print(json.dumps(score_report(load_report(args.report)).to_dict(), indent=2))
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    violations = check_policy(load_report(args.report), Policy.load(args.policy))
    if not violations:
        print("Policy check passed.")
        return 0
    print(f"Policy check failed with {len(violations)} violation(s):")
    for violation in violations:
        where = f" [{violation.target}]" if violation.target else ""
        print(f"  - {violation.rule}{where}: {violation.message}")
    return 2


def _cmd_diff(args: argparse.Namespace) -> int:
    drift = diff_reports(load_report(args.base), load_report(args.head))
    if args.json:
        print(json.dumps(drift.to_dict(), indent=2))
    else:
        print(f"Risk score: {drift.score_before} -> {drift.score_after}")
        for finding in drift.new_findings:
            print(f"  + NEW      [{finding['severity']}] {finding['id']} {finding['title']}")
        for finding in drift.resolved_findings:
            print(f"  - RESOLVED [{finding['severity']}] {finding['id']} {finding['title']}")
        for change in drift.port_changes:
            print(f"  ~ {change['target']}:{change['port']} {change['before']} -> {change['after']}")
        for change in drift.waf_changes:
            print(f"  ~ {change['url']} WAF: {change['before']} -> {change['after']}")
        if drift.firewall_change:
            print(f"  ~ host firewall active: {drift.firewall_change['before']} -> {drift.firewall_change['after']}")
        if not drift.changed:
            print("  No changes.")
    return 3 if drift.changed and args.fail_on_change else 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from wallscope.server import serve

    serve(args.host, args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wallscope-hub", description="WallScope platform layer. By ZaKari Perry.")
    parser.add_argument("--version", action="version", version=f"wallscope-hub {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="run the engine and save a JSON report")
    scan.add_argument("--local", action="store_true", help="audit this machine's firewall")
    scan.add_argument("--targets", help="comma-separated hosts to probe")
    scan.add_argument("--ports", default="top", help="port list, e.g. top or 22,80,443")
    scan.add_argument("--urls", help="comma-separated URLs to check for a WAF")
    scan.add_argument("--passive", action="store_true", help="WAF: send no test request")
    scan.add_argument("--insecure", action="store_true", help="WAF: accept invalid TLS certificates")
    scan.add_argument("--authorized", action="store_true", help="confirm you may test every remote target")
    scan.add_argument("--out", default="reports/latest.json", help="where to save the report")
    scan.set_defaults(handler=_cmd_scan)

    rep = commands.add_parser("report", help="render a report as Markdown, HTML or SARIF")
    rep.add_argument("report")
    rep.add_argument("--format", choices=("md", "html", "sarif"), default="md")
    rep.add_argument("--out")
    rep.set_defaults(handler=_cmd_report)

    score = commands.add_parser("score", help="print the risk score for a report")
    score.add_argument("report")
    score.set_defaults(handler=_cmd_score)

    check = commands.add_parser("check", help="check a report against a policy file (exit 2 on violation)")
    check.add_argument("report")
    check.add_argument("--policy", required=True)
    check.set_defaults(handler=_cmd_check)

    diff = commands.add_parser("diff", help="show what changed between two reports")
    diff.add_argument("base")
    diff.add_argument("head")
    diff.add_argument("--json", action="store_true")
    diff.add_argument("--fail-on-change", action="store_true", help="exit 3 if anything changed")
    diff.set_defaults(handler=_cmd_diff)

    srv = commands.add_parser("serve", help="start the local dashboard")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8787)
    srv.set_defaults(handler=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (EngineError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
