import json

import pytest

from auditor.report import (
    ReportError,
    build_report,
    deduplicate,
    normalize_violation,
    process_violations,
    validate_report,
    write_report,
)
from tests.conftest import violation
from tools import RepoTools


def test_normalize_fixes_case_aliases_and_unknown_ids():
    v, err = normalize_violation(violation(severity="HIGH", category="CI/CD", rule_id="weird", file="./x.yml"))
    assert err is None
    assert v["severity"] == "high" and v["category"] == "ci_cd" and v["rule_id"] == "CI-099"
    assert v["file"] == "x.yml"


def test_catalog_rule_id_decides_category():
    v, _ = normalize_violation(violation(rule_id="TST-001", category="security"))
    assert v["category"] == "testing"


def test_normalize_rejects_bad_severity_and_missing_fields():
    assert normalize_violation(violation(severity="urgent"))[0] is None
    assert normalize_violation(violation(evidence=""))[0] is None
    assert normalize_violation("nope")[0] is None


def test_line_is_null_when_file_is_null_or_invalid():
    v, _ = normalize_violation(violation(file=None, line=5))
    assert v["line"] is None
    v, _ = normalize_violation(violation(line="0"))
    assert v["line"] is None
    v, _ = normalize_violation(violation(line="12"))
    assert v["line"] == 12


def test_secret_values_are_scrubbed_from_text_fields():
    key = "AKIA" + "Q3EGRTZXMPLW7Y2B"
    v, _ = normalize_violation(violation(evidence=f"found {key} in file"))
    assert key not in v["evidence"]


def test_grounding_rejects_unseen_missing_and_out_of_range(repo_factory):
    repo = repo_factory({"config.py": "a = 1\nb = 2\n", "other.py": "x\n"})
    tools = RepoTools(repo, "main")
    tools.read_file("config.py")
    accepted, rejected = process_violations(
        [
            violation(),  # grounded: config.py line 2 was read
            violation(rule_id="SEC-003", file="ghost.py", line=None),  # does not exist
            violation(rule_id="CFG-001", file="other.py", line=1),  # never inspected
            violation(rule_id="CQ-003", file="config.py", line=99),  # beyond EOF
            violation(rule_id="HYG-001", file=None, line=None, category="repository_hygiene"),  # repo-wide
        ],
        tools,
    )
    assert {v["rule_id"] for v in accepted} == {"SEC-001", "HYG-001"}
    reasons = " | ".join(r.reason for r in rejected)
    assert "does not exist" in reasons and "never inspected" in reasons and "beyond the end" in reasons


def test_grounding_accepts_directory_findings(repo_factory):
    repo = repo_factory({"__pycache__/m.cpython-312.pyc": b"\x00bin", "m.py": "x\n"})
    tools = RepoTools(repo, "main")
    tools.list_files()
    accepted, _ = process_violations([violation(rule_id="HYG-004", category="repository_hygiene",
                                                severity="low", file="__pycache__", line=None)], tools)
    assert len(accepted) == 1


def test_deduplicate_merges_same_rule_and_location():
    a = normalize_violation(violation(severity="high"))[0]
    b = normalize_violation(violation(severity="critical"))[0]
    c = normalize_violation(violation(line=None))[0]
    d = normalize_violation(violation(rule_id="SEC-003", file=".env", line=None))[0]
    result = deduplicate([a, b, c, d])
    assert len(result) == 2
    assert result[0]["severity"] == "critical"


def test_report_contract_and_atomic_write(tmp_path):
    v = normalize_violation(violation())[0]
    report = build_report("https://github.com/o/r", [v])
    assert validate_report(report) == []
    path = write_report(report, tmp_path / "out" / "report.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert list(data) == ["repository", "violations"]
    assert set(data["violations"][0]) == {"rule_id", "category", "severity", "file", "line",
                                          "description", "evidence", "recommendation"}


def test_empty_report_is_valid(tmp_path):
    path = write_report(build_report("https://github.com/o/r", []), tmp_path / "r.json")
    assert json.loads(path.read_text())["violations"] == []


def test_invalid_report_is_refused(tmp_path):
    with pytest.raises(ReportError):
        write_report({"repository": "x", "violations": [{"severity": "bad"}]}, tmp_path / "r.json")


def test_grounding_accepts_deleted_files_seen_in_history(repo_factory):
    from tests.conftest import add_commit

    repo = repo_factory({"deploy.sh": "TOKEN='Zq8LmN3pWx7Kd2'\n"})
    add_commit(repo, {"deploy.sh": None}, "remove deploy script")
    tools = RepoTools(repo, "main")
    claim = violation(rule_id="SEC-002", severity="high", file="deploy.sh", line=1)
    accepted, rejected = process_violations([claim], tools)
    assert accepted == [] and "does not exist" in rejected[0].reason  # never observed
    tools.scan_secrets()
    accepted, _ = process_violations([claim], tools)
    assert len(accepted) == 1 and accepted[0]["line"] is None
