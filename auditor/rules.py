"""Rule-ID catalog.

The catalog gives findings stable, comparable identifiers. It is *not* a
checklist that is executed: the LLM decides what to investigate and only uses
an ID once it has evidence. Each category also has a ``-099`` catch-all ID for
genuine violations that do not fit a predefined rule.
"""

from __future__ import annotations

from dataclasses import dataclass

CATEGORIES: dict[str, str] = {
    "repository_hygiene": "HYG",
    "dependency_management": "DEP",
    "code_quality": "CQ",
    "testing": "TST",
    "ci_cd": "CI",
    "security": "SEC",
    "configuration": "CFG",
    "collaboration": "COL",
    "build_release": "BLD",
}

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    typical_severity: str


RULES: list[Rule] = [
    # Repository hygiene
    Rule("HYG-001", "repository_hygiene", "README missing or empty", "medium"),
    Rule("HYG-002", "repository_hygiene", "No .gitignore although the project produces ignorable artefacts", "medium"),
    Rule("HYG-003", "repository_hygiene", ".gitignore misses essential entries for the stack (e.g. .env, __pycache__, venv, node_modules)", "low"),
    Rule("HYG-004", "repository_hygiene", "Generated/temporary files tracked in git (bytecode, caches, build output, logs, OS files, virtualenvs)", "low"),
    Rule("HYG-005", "repository_hygiene", "Large binaries or archives committed to the repository", "low"),
    Rule("HYG-006", "repository_hygiene", "README lacks essential setup/usage instructions", "low"),
    # Dependency management
    Rule("DEP-001", "dependency_management", "Code has third-party imports but no dependency manifest", "high"),
    Rule("DEP-002", "dependency_management", "Unpinned or weakly constrained dependencies for an application", "medium"),
    Rule("DEP-003", "dependency_management", "Inconsistent dependency specifications across manifests", "medium"),
    Rule("DEP-004", "dependency_management", "Lockfile missing for a tool that requires one, or lockfile clearly out of sync", "medium"),
    Rule("DEP-005", "dependency_management", "Imported package not declared / dev tools mixed into runtime deps", "medium"),
    Rule("DEP-006", "dependency_management", "Insecure dependency source (http index, trusted-host, unpinned VCS ref)", "high"),
    # Code quality
    Rule("CQ-001", "code_quality", "No linter/formatter configured or enforced anywhere", "low"),
    Rule("CQ-002", "code_quality", "Static analysis finds real errors (syntax errors, undefined names, unused imports at scale)", "medium"),
    Rule("CQ-003", "code_quality", "Obvious maintainability problem (bare except swallowing errors, duplicated modules, dead code)", "low"),
    # Testing
    Rule("TST-001", "testing", "No automated tests", "high"),
    Rule("TST-002", "testing", "Tests exist but CI never runs them", "high"),
    Rule("TST-003", "testing", "Tests are broken, trivially passing, or skipped/disabled", "medium"),
    # CI/CD
    Rule("CI-001", "ci_cd", "No continuous integration configured", "medium"),
    Rule("CI-002", "ci_cd", "Incorrect workflow triggers (wrong branch, never runs on PR/push, bad path filters)", "high"),
    Rule("CI-003", "ci_cd", "Ineffective gate: failures masked (continue-on-error, || true, exit 0)", "high"),
    Rule("CI-004", "ci_cd", "Validation skipped or disabled (if: false, skip flags, commented-out steps)", "high"),
    Rule("CI-005", "ci_cd", "Third-party action referenced by mutable branch or without version", "medium"),
    Rule("CI-006", "ci_cd", "Invalid workflow definition (YAML/schema error, job that cannot run)", "high"),
    Rule("CI-007", "ci_cd", "Deprecated action versions, runners, or workflow commands", "low"),
    Rule("CI-008", "ci_cd", "Configured quality checks (lint/type-check) not executed in CI", "low"),
    # Security
    Rule("SEC-001", "security", "Hardcoded credential in source or configuration", "critical"),
    Rule("SEC-002", "security", "Credential present in git history", "high"),
    Rule("SEC-003", "security", "Sensitive file tracked (.env, private key, credentials file)", "critical"),
    Rule("SEC-004", "security", "Overly broad GITHUB_TOKEN permissions in workflows", "high"),
    Rule("SEC-005", "security", "pull_request_target/workflow_run executes untrusted PR code with secrets", "critical"),
    Rule("SEC-006", "security", "Script injection: untrusted event data interpolated into run commands", "high"),
    Rule("SEC-007", "security", "Secrets exposed in logs or artefacts", "high"),
    Rule("SEC-008", "security", "Insecure code/config defaults (debug in production, TLS verification disabled, shell injection)", "high"),
    Rule("SEC-009", "security", "Remote script piped to shell without verification", "medium"),
    # Configuration
    Rule("CFG-001", "configuration", "Machine-specific absolute paths in code or config", "medium"),
    Rule("CFG-002", "configuration", "Committed local/IDE/user-specific settings", "low"),
    Rule("CFG-003", "configuration", "No environment separation (environment-specific values hardcoded, prod settings as defaults)", "medium"),
    Rule("CFG-004", "configuration", "Required environment variables undocumented (no .env.example or docs)", "low"),
    # Collaboration
    Rule("COL-001", "collaboration", "Unsafe PR automation (auto-merge/approve without checks, bot with excessive rights)", "high"),
    Rule("COL-002", "collaboration", "No contribution/review guidance in a clearly multi-contributor project", "low"),
    # Build & release
    Rule("BLD-001", "build_release", "Build/packaging never validated in CI", "medium"),
    Rule("BLD-002", "build_release", "Risky deployment automation (deploy without tests/needs, deploy from PRs, no environment gate)", "high"),
    Rule("BLD-003", "build_release", "Risky release publishing (long-lived tokens, publish on every push, no version gate)", "high"),
    Rule("BLD-004", "build_release", "Container build issues (unpinned/latest base image, runs as root, secrets in image, no .dockerignore with COPY .)", "medium"),
    Rule("BLD-005", "build_release", "Inconsistent version metadata across files", "low"),
]

RULES_BY_ID = {r.id: r for r in RULES}


def catch_all_id(category: str) -> str:
    return f"{CATEGORIES.get(category, 'GEN')}-099"


def render_catalog() -> str:
    """Catalog text embedded in the system prompt."""
    lines = []
    for category, prefix in CATEGORIES.items():
        lines.append(f"[{category}]")
        for r in RULES:
            if r.category == category:
                lines.append(f"  {r.id} ({r.typical_severity}): {r.title}")
        lines.append(f"  {prefix}-099: other genuine {category} violation")
    return "\n".join(lines)
