import copy

import pytest

from wallscope.analysis import Policy, check_policy, diff_reports, score_report


def test_clean_report_scores_zero_grade_a(clean):
    risk = score_report(clean)
    assert (risk.score, risk.grade) == (0, "A")


def test_sample_score_is_capped_and_counts_by_severity(sample):
    risk = score_report(sample)
    assert risk.score == 100
    assert risk.grade == "F"
    assert risk.counts == {"info": 2, "low": 1, "medium": 2, "high": 3, "critical": 1}


@pytest.mark.parametrize(
    ("severities", "score", "grade"),
    [(["low"], 3, "A"), (["medium", "low"], 11, "B"), (["high", "medium"], 28, "C"), (["critical", "high"], 60, "D")],
)
def test_grade_boundaries(clean, severities, score, grade):
    clean["findings"] = [{"id": f"X-{i}", "severity": s, "title": "t"} for i, s in enumerate(severities)]
    risk = score_report(clean)
    assert (risk.score, risk.grade) == (score, grade)


def test_policy_reports_each_kind_of_violation(sample):
    policy = Policy.from_dict(
        {"policy": {"max_risk_score": 40, "fail_on": "critical", "require_waf": True, "forbidden_open_ports": [3389, 23]}}
    )
    rules = [v.rule for v in check_policy(sample, policy)]
    assert rules.count("max_risk_score") == 1
    assert rules.count("fail_on") == 1
    assert rules.count("require_waf") == 1
    assert rules.count("forbidden_open_ports") == 1


def test_policy_ignore_removes_findings_from_consideration(sample):
    policy = Policy.from_dict({"fail_on": "critical", "ignore": ["LOCAL-002"]})
    assert check_policy(sample, policy) == []


def test_policy_requires_confirmed_local_firewall(clean):
    policy = Policy.from_dict({"require_local_firewall": True})
    assert check_policy(clean, policy) == []
    clean["localAudit"]["firewallActive"] = None
    assert [v.rule for v in check_policy(clean, policy)] == ["require_local_firewall"]
    del clean["localAudit"]
    assert [v.rule for v in check_policy(clean, policy)] == ["require_local_firewall"]


@pytest.mark.parametrize("bad", [{"nonsense": 1}, {"fail_on": "catastrophic"}])
def test_policy_rejects_bad_settings(bad):
    with pytest.raises(ValueError):
        Policy.from_dict(bad)


def test_policy_loads_from_toml(tmp_path, sample):
    path = tmp_path / "policy.toml"
    path.write_text('[policy]\nmax_risk_score = 100\nfail_on = "critical"\n', encoding="utf-8")
    assert len(check_policy(sample, Policy.load(path))) == 1


def test_identical_reports_have_no_drift(sample):
    drift = diff_reports(sample, copy.deepcopy(sample))
    assert not drift.changed


def test_drift_tracks_findings_ports_waf_and_firewall(sample):
    head = copy.deepcopy(sample)
    head["findings"] = [f for f in head["findings"] if f["id"] != "LOCAL-002"]
    head["findings"].append({"id": "NET-003", "severity": "critical", "title": "Sensitive service reachable: 23/telnet", "target": "db01.example.com"})
    next(p for p in head["networkProbes"][1]["ports"] if p["port"] == 23)["state"] = "open"
    head["wafResults"][1]["matches"] = [{"name": "ModSecurity", "confidence": 70}]
    head["localAudit"]["firewallActive"] = False

    drift = diff_reports(sample, head)

    assert [f["title"] for f in drift.new_findings] == ["Sensitive service reachable: 23/telnet"]
    assert [f["id"] for f in drift.resolved_findings] == ["LOCAL-002"]
    assert drift.port_changes == [{"target": "db01.example.com", "port": 23, "before": "closed", "after": "open"}]
    assert drift.waf_changes == [{"url": "https://legacy.example.com/", "before": "none", "after": "ModSecurity"}]
    assert drift.firewall_change == {"before": True, "after": False}
    assert drift.to_dict()["changed"] is True
