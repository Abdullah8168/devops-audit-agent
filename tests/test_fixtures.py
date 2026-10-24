"""The evaluation fixtures build correctly and the tools surface each injected defect."""

import pytest

from eval import run_eval
from eval.fixtures import FIXTURE_A, FIXTURE_B, FIXTURE_C
from tools import RepoTools


@pytest.fixture
def build(tmp_path, monkeypatch):
    monkeypatch.setattr(run_eval, "WORKDIR", tmp_path)
    return lambda fixture: RepoTools(run_eval.build_fixture(fixture), "main")


def test_fixture_a_evidence(build):
    t = build(FIXTURE_A)
    files = t.list_files()
    assert "README.md" not in files and ".gitignore" not in files and "__pycache__/" in files
    secrets = t.scan_secrets()
    assert "Sensitive files tracked in git: .env" in secrets and "config.py:4 [aws_access_key_id]" in secrets
    assert "UNPINNED=3" in t.inspect_dependencies()


def test_fixture_b_evidence(build):
    t = build(FIXTURE_B)
    wf = t.inspect_workflows()
    for needle in ("do not include the default branch 'main'", "|| true", "pull_request_target",
                   "write-all", "checks out pull-request head code", "untrusted github context"):
        assert needle in wf, needle
    assert "scripts/deploy.sh [hardcoded_credential] (file no longer tracked)" in t.scan_secrets()
    assert "requests: ['==2.31.0', '>=2.20,<2.30']" in t.inspect_dependencies()
    assert "metrics/settings.py:5:" in t.search_code(r"C:/Users")


def test_fixture_c_is_clean_for_the_tools(build):
    t = build(FIXTURE_C)
    wf = t.inspect_workflows()
    assert "observations:" not in wf
    secrets = t.scan_secrets()
    assert "documented example" in secrets
    assert "Sensitive files tracked in git: none" in secrets
    assert "ruff: no issues found" in t.run_ruff()


def test_answer_keys_use_catalog_rule_ids():
    from auditor.rules import RULES_BY_ID

    for fixture in (FIXTURE_A, FIXTURE_B):
        for item in fixture["expected"] + fixture["acceptable"]:
            for rule_id in item["rule_ids"]:
                assert rule_id in RULES_BY_ID, rule_id


def test_scoring_counts_duplicates_as_false_positives():
    def v(rule_id, file):
        return {"rule_id": rule_id, "file": file, "description": "d"}

    report = {"violations": [v("HYG-001", None), v("HYG-001", None), v("CQ-099", "x.py")]}
    s = run_eval.score(FIXTURE_A, report)
    assert s["true_positives"] == 1 and len(s["false_positives"]) == 2
