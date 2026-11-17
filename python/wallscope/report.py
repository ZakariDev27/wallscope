"""Renders engine reports as Markdown, a standalone HTML page, or SARIF for code-scanning tools."""

from __future__ import annotations

from html import escape

from wallscope import __version__
from wallscope.analysis import score_report, severity_rank

_SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}
_SEVERITY_COLOR = {
    "info": "#7fb2e5",
    "low": "#5aa0d8",
    "medium": "#d9a23c",
    "high": "#e0703a",
    "critical": "#d64545",
}


def _sorted_findings(report: dict) -> list[dict]:
    return sorted(
        report.get("findings", []),
        key=lambda f: (-severity_rank(str(f.get("severity", "info"))), str(f.get("id"))),
    )


def _waf_summary(result: dict) -> str:
    if result.get("error"):
        return f"could not be checked ({result['error']})"
    matches = result.get("matches", [])
    if matches:
        return ", ".join(f"{m['name']} ({m['confidence']}%)" for m in matches)
    return "unidentified WAF behaviour" if result.get("genericBlockingObserved") else "none detected"


def to_markdown(report: dict) -> str:
    risk = score_report(report)
    lines = [
        "# WallScope report",
        "",
        f"**Host:** {report.get('host', '?')}  ",
        f"**System:** {report.get('os', '?')}  ",
        f"**Finished:** {report.get('finishedUtc', '?')}  ",
        f"**Risk:** {risk.score}/100, grade {risk.grade} ({risk.posture})",
        "",
    ]

    audit = report.get("localAudit")
    if audit:
        state = {True: "active", False: "NOT active"}.get(audit.get("firewallActive"), "unknown")
        lines += ["## Local firewall", "", f"State: **{state}**", ""]
        installed = [b for b in audit.get("backends", []) if b.get("state") != "notInstalled"]
        if installed:
            lines += ["| Backend | State | Detail |", "| --- | --- | --- |"]
            lines += [
                f"| {b['name']} | {b['state']} | {b.get('detail') or b.get('error') or ''} |" for b in installed
            ]
            lines.append("")

    probes = report.get("networkProbes", [])
    if probes:
        lines += ["## Network probes", "", "| Target | Verdict | Open | Closed | Filtered |", "| --- | --- | --- | --- | --- |"]
        lines += [
            f"| {p['target']} | {p.get('verdict', '')} | {p.get('open', 0)} | {p.get('closed', 0)} | {p.get('filtered', 0)} |"
            for p in probes
        ]
        lines.append("")

    waf = report.get("wafResults", [])
    if waf:
        lines += ["## Web application firewalls", "", "| URL | Result |", "| --- | --- |"]
        lines += [f"| {r['url']} | {_waf_summary(r)} |" for r in waf]
        lines.append("")

    findings = _sorted_findings(report)
    lines += [f"## Findings ({len(findings)})", ""]
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        target = f" on `{finding['target']}`" if finding.get("target") else ""
        lines.append(f"### {finding['severity'].upper()}: {finding['title']}{target}")
        lines += ["", f"`{finding['id']}`. {finding['detail']}", ""]
        if finding.get("remediation"):
            lines += [f"**Fix:** {finding['remediation']}", ""]

    return "\n".join(lines).rstrip() + "\n"


def to_html(report: dict) -> str:
    risk = score_report(report)
    rows = []
    for finding in _sorted_findings(report):
        severity = str(finding.get("severity", "info"))
        fix = f"<p class='fix'><b>Fix:</b> {escape(finding['remediation'])}</p>" if finding.get("remediation") else ""
        target = f"<span class='target'>{escape(finding['target'])}</span>" if finding.get("target") else ""
        rows.append(
            f"<article><span class='sev' style='background:{_SEVERITY_COLOR.get(severity, '#7fb2e5')}'>"
            f"{escape(severity)}</span><h3>{escape(finding['title'])}</h3>{target}"
            f"<p><code>{escape(finding['id'])}</code> {escape(finding['detail'])}</p>{fix}</article>"
        )

    probes = "".join(
        f"<tr><td>{escape(p['target'])}</td><td>{escape(str(p.get('verdict', '')))}</td>"
        f"<td>{p.get('open', 0)}</td><td>{p.get('closed', 0)}</td><td>{p.get('filtered', 0)}</td></tr>"
        for p in report.get("networkProbes", [])
    )
    waf = "".join(
        f"<tr><td>{escape(r['url'])}</td><td>{escape(_waf_summary(r))}</td></tr>" for r in report.get("wafResults", [])
    )
    audit = report.get("localAudit")
    local = ""
    if audit:
        state = {True: "active", False: "NOT active"}.get(audit.get("firewallActive"), "unknown")
        local = f"<h2>Local firewall</h2><p>State: <b>{state}</b></p>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WallScope report - {escape(str(report.get('host', '')))}</title>
<style>
body{{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0a1730;color:#dfe7f2}}
main{{max-width:880px;margin:0 auto;padding:40px 24px 64px}}
h1{{margin:0;font-size:28px;color:#fff}} h2{{margin:36px 0 12px;font-size:18px;color:#8ec5ff}}
.by{{color:#8b9bb3;margin:4px 0 28px}} .score{{display:flex;gap:20px;align-items:center;background:#112346;border:1px solid #1f3a6b;border-radius:14px;padding:20px 24px}}
.score b{{font-size:44px;color:#8ec5ff;line-height:1}} .meta{{color:#8b9bb3}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1f3a6b}} th{{color:#8b9bb3;font-weight:600}}
article{{background:#112346;border:1px solid #1f3a6b;border-radius:12px;padding:16px 18px;margin:10px 0}}
article h3{{display:inline;margin:0 0 0 10px;font-size:16px;color:#fff}} .sev{{color:#06122a;font-weight:700;font-size:11px;text-transform:uppercase;padding:3px 8px;border-radius:99px}}
.target{{display:block;color:#8b9bb3;font-size:13px;margin-top:6px;word-break:break-all}} .fix{{color:#b8c6da}} code{{color:#8ec5ff}}
</style></head><body><main>
<h1>WallScope report</h1><p class="by">By ZaKari Perry &middot; generated by WallScope {escape(__version__)}</p>
<div class="score"><b>{risk.score}</b><div><div>Risk score out of 100 &middot; grade {risk.grade} &middot; {escape(risk.posture)}</div>
<div class="meta">{escape(str(report.get('host', '')))} &middot; {escape(str(report.get('os', '')))} &middot; {escape(str(report.get('finishedUtc', '')))}</div></div></div>
{local}
{"<h2>Network probes</h2><table><tr><th>Target</th><th>Verdict</th><th>Open</th><th>Closed</th><th>Filtered</th></tr>" + probes + "</table>" if probes else ""}
{"<h2>Web application firewalls</h2><table><tr><th>URL</th><th>Result</th></tr>" + waf + "</table>" if waf else ""}
<h2>Findings ({len(rows)})</h2>
{"".join(rows) or "<p>No findings.</p>"}
</main></body></html>
"""


def to_sarif(report: dict) -> dict:
    """SARIF 2.1.0, so findings can be uploaded to GitHub code scanning or any SARIF viewer."""
    rules: dict[str, dict] = {}
    results = []
    for finding in _sorted_findings(report):
        rule_id = str(finding.get("id"))
        severity = str(finding.get("severity", "info"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": finding.get("title", rule_id)},
                "help": {"text": finding.get("remediation") or finding.get("detail", "")},
            },
        )
        target = finding.get("target") or report.get("host", "host")
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(severity, "note"),
                "message": {"text": f"{finding.get('title')}: {finding.get('detail')}"},
                "locations": [{"logicalLocations": [{"name": str(target), "kind": "resource"}]}],
                "properties": {"severity": severity, "module": finding.get("module")},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "WallScope",
                        "version": __version__,
                        "informationUri": "https://github.com/ZakariDev27/wallscope",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
