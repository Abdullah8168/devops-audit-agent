"""Validation, evidence grounding, de-duplication and output of violations.

The LLM proposes violations; this module decides what is allowed into the final
report:

1. **Schema validation**: all required fields present, severity and category
   from the allowed sets, line is a positive integer or null.
2. **Evidence grounding**: a finding that names a file must refer to a file that
   exists and that the agent actually observed through a tool. A finding with a
   line number must point at content the agent saw, and at a line that exists.
3. **Redaction**: all text fields are scrubbed so no secret value can leak.
4. **De-duplication**: one finding per (rule, file, line); duplicates are merged.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from auditor.redaction import redact
from auditor.rules import CATEGORIES, RULES_BY_ID, SEVERITIES, catch_all_id

REQUIRED_FIELDS = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
RULE_ID = re.compile(r"^[A-Z]{2,4}-\d{3}$")

_CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene",
    "repository hygiene": "repository_hygiene",
    "repo_hygiene": "repository_hygiene",
    "dependencies": "dependency_management",
    "dependency management": "dependency_management",
    "code quality": "code_quality",
    "quality": "code_quality",
    "tests": "testing",
    "test": "testing",
    "ci": "ci_cd",
    "ci/cd": "ci_cd",
    "cicd": "ci_cd",
    "github actions": "ci_cd",
    "github_actions": "ci_cd",
    "github actions / ci": "ci_cd",
    "config": "configuration",
    "build": "build_release",
    "build and release": "build_release",
    "build & release": "build_release",
    "release": "build_release",
}
_SEVERITY_ALIASES = {"crit": "critical", "major": "high", "moderate": "medium", "minor": "low", "info": "low"}


class ReportError(Exception):
    """The report could not be written."""


@dataclass
class Rejection:
    violation: dict[str, Any]
    reason: str

    def describe(self) -> str:
        v = self.violation
        where = v.get("file") or "<repo>"
        if v.get("line"):
            where += f":{v['line']}"
        return f"- {v.get('rule_id', '?')} at {where}: {self.reason}"


def normalize_category(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in CATEGORIES:
        return text
    text = _CATEGORY_ALIASES.get(text, text.replace(" ", "_").replace("-", "_"))
    return text if text in CATEGORIES else None


def normalize_violation(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Return a cleaned violation, or ``(None, reason)`` when it is unusable."""
    if not isinstance(raw, dict):
        return None, "violation is not an object"
    missing = [f for f in ("description", "evidence", "recommendation") if not str(raw.get(f) or "").strip()]
    if missing:
        return None, f"missing required field(s): {', '.join(missing)}"

    rule_id = str(raw.get("rule_id") or "").strip().upper()
    category = normalize_category(raw.get("category"))
    if rule_id in RULES_BY_ID:
        category = RULES_BY_ID[rule_id].category  # the catalog is authoritative
    if category is None:
        return None, f"unknown category {raw.get('category')!r}"
    if not RULE_ID.match(rule_id):
        rule_id = catch_all_id(category)

    severity = str(raw.get("severity") or "").strip().lower()
    severity = _SEVERITY_ALIASES.get(severity, severity)
    if severity not in SEVERITIES:
        return None, f"invalid severity {raw.get('severity')!r}"

    file = raw.get("file")
    if isinstance(file, str):
        file = file.strip().replace("\\", "/")
        while file.startswith("./"):
            file = file[2:]
        file = file.strip("/")
        if file.lower() in ("", "null", "none", "n/a", "-", "."):
            file = None
    elif file is not None:
        file = None

    line = raw.get("line")
    if isinstance(line, str) and line.strip().isdigit():
        line = int(line.strip())
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        line = None
    if file is None:
        line = None

    clean = {
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "file": file,
        "line": line,
        "description": redact(str(raw["description"]).strip()),
        "evidence": redact(str(raw["evidence"]).strip()),
        "recommendation": redact(str(raw["recommendation"]).strip()),
    }
    return clean, None


class EvidenceIndex:
    """What the agent has observed; implemented by :class:`tools.RepoTools`."""

    listed_files: set[str]
    content_seen: dict[str, set[int] | None]

    def file_exists(self, path: str) -> bool: ...  # pragma: no cover

    def line_count(self, path: str) -> int | None: ...  # pragma: no cover


def ground(violation: dict[str, Any], evidence: Any) -> str | None:
    """Return ``None`` if the violation is grounded, otherwise the reason it is not."""
    file, line = violation["file"], violation["line"]
    if file is None:
        return None
    if not evidence.file_exists(file):
        # Directory-level findings (e.g. "build/ is tracked") are fine if the agent saw files inside it.
        if any(f.startswith(file + "/") for f in evidence.listed_files):
            violation["line"] = None
            return None
        return f"file '{file}' does not exist in the repository"
    if file not in evidence.listed_files and file not in evidence.content_seen:
        return f"file '{file}' was never inspected with a tool"
    if line is None:
        return None
    seen = evidence.content_seen.get(file, set())
    if file not in evidence.content_seen:
        return f"line {line} of '{file}' cited but the file's content was never read"
    total = evidence.line_count(file)
    if total is not None and line > total:
        return f"line {line} is beyond the end of '{file}' ({total} lines)"
    if seen is not None and line not in seen:
        return f"line {line} of '{file}' was not among the lines the agent inspected"
    return None


def deduplicate(violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge duplicates: same rule and location, or same rule+file where one lacks a line."""
    result: list[dict[str, Any]] = []
    for v in violations:
        dup = None
        for kept in result:
            if kept["rule_id"] != v["rule_id"] or kept["file"] != v["file"]:
                continue
            if kept["line"] == v["line"] or kept["line"] is None or v["line"] is None:
                dup = kept
                break
        if dup is None:
            result.append(dict(v))
            continue
        # Keep the more severe / more specific of the two.
        if SEVERITY_ORDER[v["severity"]] < SEVERITY_ORDER[dup["severity"]]:
            dup["severity"] = v["severity"]
        if dup["line"] is None and v["line"] is not None:
            dup["line"] = v["line"]
    return sorted(result, key=lambda v: (SEVERITY_ORDER[v["severity"]], v["category"], v["file"] or "", v["line"] or 0))


def process_violations(
    raw_violations: list[Any], evidence: Any
) -> tuple[list[dict[str, Any]], list[Rejection]]:
    """Validate and ground raw violations; returns (accepted, rejected)."""
    accepted: list[dict[str, Any]] = []
    rejected: list[Rejection] = []
    for raw in raw_violations or []:
        clean, problem = normalize_violation(raw)
        if clean is None:
            rejected.append(Rejection(raw if isinstance(raw, dict) else {"raw": str(raw)}, problem or "invalid"))
            continue
        reason = ground(clean, evidence)
        if reason:
            rejected.append(Rejection(clean, reason))
        else:
            accepted.append(clean)
    return deduplicate(accepted), rejected


def build_report(repository: str, violations: list[dict[str, Any]]) -> dict[str, Any]:
    return {"repository": repository, "violations": [{k: v[k] for k in REQUIRED_FIELDS} for v in violations]}


def validate_report(report: Any) -> list[str]:
    """Check a report against the output contract; returns a list of problems (empty = valid)."""
    problems: list[str] = []
    if not isinstance(report, dict):
        return ["report must be a JSON object"]
    if not isinstance(report.get("repository"), str):
        problems.append("'repository' must be a string")
    violations = report.get("violations")
    if not isinstance(violations, list):
        return problems + ["'violations' must be an array"]
    for i, v in enumerate(violations):
        if not isinstance(v, dict):
            problems.append(f"violations[{i}] is not an object")
            continue
        for field in REQUIRED_FIELDS:
            if field not in v:
                problems.append(f"violations[{i}] missing '{field}'")
        if v.get("severity") not in SEVERITIES:
            problems.append(f"violations[{i}] has invalid severity {v.get('severity')!r}")
        if v.get("file") is not None and not isinstance(v.get("file"), str):
            problems.append(f"violations[{i}].file must be a string or null")
        line = v.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int)):
            problems.append(f"violations[{i}].line must be an integer or null")
    return problems


def write_report(report: dict[str, Any], output: str | Path) -> Path:
    """Validate and atomically write the report as UTF-8 JSON."""
    problems = validate_report(report)
    if problems:
        raise ReportError("internal error, report failed validation: " + "; ".join(problems))
    path = Path(output)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".json", dir=str(path.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except OSError as exc:
        raise ReportError(f"could not write report to {path}: {exc}") from exc
    return path
