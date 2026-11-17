"""Risk scoring, policy-as-code checks and drift detection over engine reports."""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")
WEIGHTS = {"info": 0, "low": 3, "medium": 8, "high": 20, "critical": 40}
GRADES = ((10, "A", "Strong"), (25, "B", "Good"), (50, "C", "Needs attention"), (75, "D", "Weak"), (101, "F", "Exposed"))


def severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity.lower())
    except ValueError:
        return 0


# ---------- scoring ----------


@dataclass(frozen=True)
class RiskScore:
    score: int
    grade: str
    posture: str
    counts: dict[str, int]

    def to_dict(self) -> dict:
        return asdict(self)


def score_report(report: dict) -> RiskScore:
    """0 is clean, 100 is as bad as it gets. Each finding adds its severity weight, capped at 100."""
    counts = {name: 0 for name in SEVERITIES}
    for finding in report.get("findings", []):
        name = str(finding.get("severity", "info")).lower()
        counts[name if name in counts else "info"] += 1

    score = min(100, sum(WEIGHTS[name] * count for name, count in counts.items()))
    grade, posture = next((g, p) for limit, g, p in GRADES if score < limit)
    return RiskScore(score, grade, posture, counts)


# ---------- policy ----------


@dataclass(frozen=True)
class Policy:
    max_risk_score: int | None = None
    fail_on: str | None = None
    require_local_firewall: bool = False
    require_waf: bool = False
    forbidden_open_ports: tuple[int, ...] = ()
    ignore: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        section = data.get("policy", data)
        unknown = set(section) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"Unknown policy setting(s): {', '.join(sorted(unknown))}")
        fail_on = section.get("fail_on")
        if fail_on is not None and str(fail_on).lower() not in SEVERITIES:
            raise ValueError(f"fail_on must be one of {', '.join(SEVERITIES)}")
        return cls(
            max_risk_score=section.get("max_risk_score"),
            fail_on=str(fail_on).lower() if fail_on else None,
            require_local_firewall=bool(section.get("require_local_firewall", False)),
            require_waf=bool(section.get("require_waf", False)),
            forbidden_open_ports=tuple(int(p) for p in section.get("forbidden_open_ports", ())),
            ignore=tuple(str(i) for i in section.get("ignore", ())),
        )

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, "rb") as handle:
            return cls.from_dict(tomllib.load(handle))


@dataclass(frozen=True)
class Violation:
    rule: str
    message: str
    target: str | None = None


def check_policy(report: dict, policy: Policy) -> list[Violation]:
    violations: list[Violation] = []
    findings = [f for f in report.get("findings", []) if f.get("id") not in policy.ignore]
    considered = {**report, "findings": findings}

    if policy.max_risk_score is not None:
        risk = score_report(considered)
        if risk.score > policy.max_risk_score:
            violations.append(
                Violation("max_risk_score", f"Risk score {risk.score} is above the allowed {policy.max_risk_score}.")
            )

    if policy.fail_on:
        threshold = severity_rank(policy.fail_on)
        for finding in findings:
            if severity_rank(str(finding.get("severity", "info"))) >= threshold:
                violations.append(
                    Violation(
                        "fail_on",
                        f"{finding.get('id')} ({finding.get('severity')}): {finding.get('title')}",
                        finding.get("target"),
                    )
                )

    if policy.require_local_firewall:
        audit = report.get("localAudit")
        if audit is None:
            violations.append(Violation("require_local_firewall", "The report has no local firewall audit."))
        elif audit.get("firewallActive") is not True:
            violations.append(Violation("require_local_firewall", "The host firewall is not confirmed active."))

    if policy.require_waf:
        for result in report.get("wafResults", []):
            if not result.get("detected"):
                violations.append(Violation("require_waf", "No WAF detected.", result.get("url")))

    forbidden = set(policy.forbidden_open_ports)
    for probe in report.get("networkProbes", []):
        for port in probe.get("ports", []):
            if port.get("state") == "open" and port.get("port") in forbidden:
                violations.append(
                    Violation("forbidden_open_ports", f"Port {port['port']} is open.", probe.get("target"))
                )

    return violations


# ---------- drift ----------


@dataclass
class Drift:
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    port_changes: list[dict] = field(default_factory=list)
    waf_changes: list[dict] = field(default_factory=list)
    firewall_change: dict | None = None
    score_before: int = 0
    score_after: int = 0

    @property
    def changed(self) -> bool:
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.port_changes
            or self.waf_changes
            or self.firewall_change
        )

    def to_dict(self) -> dict:
        return {**asdict(self), "changed": self.changed}


def _finding_key(finding: dict) -> tuple:
    return (finding.get("id"), finding.get("target"), finding.get("title"))


def _ports(report: dict) -> dict[tuple[str, int], str]:
    return {
        (probe.get("target", ""), port.get("port")): port.get("state", "")
        for probe in report.get("networkProbes", [])
        for port in probe.get("ports", [])
    }


def _waf(report: dict) -> dict[str, str]:
    summary = {}
    for result in report.get("wafResults", []):
        names = sorted(match.get("name", "") for match in result.get("matches", []))
        if names:
            summary[result.get("url", "")] = ", ".join(names)
        elif result.get("genericBlockingObserved"):
            summary[result.get("url", "")] = "unidentified WAF"
        else:
            summary[result.get("url", "")] = "none"
    return summary


def diff_reports(base: dict, head: dict) -> Drift:
    """What changed between an earlier report (base) and a later one (head)."""
    drift = Drift(score_before=score_report(base).score, score_after=score_report(head).score)

    before = {_finding_key(f): f for f in base.get("findings", [])}
    after = {_finding_key(f): f for f in head.get("findings", [])}
    drift.new_findings = [after[k] for k in after.keys() - before.keys()]
    drift.resolved_findings = [before[k] for k in before.keys() - after.keys()]
    for bucket in (drift.new_findings, drift.resolved_findings):
        bucket.sort(key=lambda f: (-severity_rank(str(f.get("severity", "info"))), str(f.get("id"))))

    ports_before, ports_after = _ports(base), _ports(head)
    for key in sorted(ports_before.keys() & ports_after.keys()):
        if ports_before[key] != ports_after[key]:
            drift.port_changes.append(
                {"target": key[0], "port": key[1], "before": ports_before[key], "after": ports_after[key]}
            )

    waf_before, waf_after = _waf(base), _waf(head)
    for url in sorted(waf_before.keys() & waf_after.keys()):
        if waf_before[url] != waf_after[url]:
            drift.waf_changes.append({"url": url, "before": waf_before[url], "after": waf_after[url]})

    active_before = (base.get("localAudit") or {}).get("firewallActive")
    active_after = (head.get("localAudit") or {}).get("firewallActive")
    if base.get("localAudit") and head.get("localAudit") and active_before != active_after:
        drift.firewall_change = {"before": active_before, "after": active_after}

    return drift
