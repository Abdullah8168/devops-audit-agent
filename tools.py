"""Inspection tools the agent can call.

Every tool is read-only: it inspects the cloned workspace through the filesystem
or read-only git commands and never executes code from the repository. All
output is passed through secret redaction and truncated before it is returned
to the agent, so credentials never reach the LLM, the trace log, or the report.

The :data:`TOOL_SCHEMAS` list describes the tools to the LLM in the
OpenAI-compatible function-calling format; :meth:`RepoTools.execute` dispatches
a tool call by name.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from auditor.redaction import find_secrets, redact
from auditor.repo import run_git

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

MAX_OUTPUT_CHARS = 14_000
MAX_READ_LINES = 400
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}

SENSITIVE_FILENAMES = [
    ".env", ".env.local", ".env.production", ".env.prod", ".env.dev", ".env.development",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "credentials.json", "service-account*.json", "*.tfstate", ".pypirc", ".npmrc",
    ".netrc", ".htpasswd", "secrets.yml", "secrets.yaml",
]
SENSITIVE_EXEMPT = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.example"]


class ToolError(Exception):
    """A tool could not complete; the message is returned to the agent."""


@dataclass
class ToolResult:
    name: str
    ok: bool
    output: str
    duration_s: float


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [output truncated: {len(text) - limit} more characters]"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


class RepoTools:
    """Read-only inspection tools bound to one repository checkout."""

    def __init__(self, root: Path, default_branch: str = "unknown", git_timeout: int = 60):
        self.root = Path(root).resolve()
        self.default_branch = default_branch
        self.git_timeout = git_timeout
        self._tracked: list[str] | None = None
        # Evidence bookkeeping used to ground the final report:
        self.listed_files: set[str] = set()  # paths the agent has seen exist
        self.content_seen: dict[str, set[int] | None] = {}  # path -> lines seen (None = whole file)
        self._handlers: dict[str, Callable[..., str]] = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
            "inspect_workflows": self.inspect_workflows,
            "inspect_dependencies": self.inspect_dependencies,
            "scan_secrets": self.scan_secrets,
            "run_ruff": self.run_ruff,
            "git_status": self.git_status,
        }

    # ------------------------------------------------------------------ helpers
    def tracked_files(self) -> list[str]:
        """Files tracked by git (POSIX paths). Falls back to a directory walk."""
        if self._tracked is None:
            res = run_git(["ls-files", "-z"], self.root, timeout=self.git_timeout)
            if res.returncode == 0:
                files = [f for f in res.stdout.split("\0") if f]
            else:  # not a git repo: walk the tree
                files = [
                    p.relative_to(self.root).as_posix()
                    for p in self.root.rglob("*")
                    if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
                ]
            self._tracked = sorted(files)
        return self._tracked

    def file_exists(self, path: str) -> bool:
        return self.normalize(path) in set(self.tracked_files())

    def line_count(self, path: str) -> int | None:
        try:
            return len(self._read_text(self.normalize(path)).splitlines())
        except ToolError:
            return None

    def normalize(self, path: str) -> str:
        p = (path or "").strip().replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        return p.strip("/")

    def _resolve(self, path: str) -> Path:
        """Resolve ``path`` inside the repository, refusing anything that escapes it."""
        rel = self.normalize(path)
        full = (self.root / rel).resolve()
        if full != self.root and self.root not in full.parents:
            raise ToolError(f"Path {path!r} is outside the repository")
        return full

    def _read_text(self, rel: str) -> str:
        full = self._resolve(rel)
        if not full.is_file():
            raise ToolError(f"File not found: {rel}")
        data = full.read_bytes()
        if len(data) > MAX_FILE_BYTES:
            raise ToolError(f"{rel} is too large to read ({len(data)} bytes)")
        if _is_binary(data):
            raise ToolError(f"{rel} is a binary file ({len(data)} bytes)")
        return data.decode("utf-8", errors="replace")

    def _text_files(self, glob: str | None = None) -> list[str]:
        files = self.tracked_files()
        if glob:
            patterns = [g.strip() for g in glob.split(",") if g.strip()]
            files = [
                f for f in files
                if any(fnmatch.fnmatch(f, g) or fnmatch.fnmatch(PurePosixPath(f).name, g) for g in patterns)
            ]
        return files

    def _mark_seen(self, path: str, lines: set[int] | None) -> None:
        path = self.normalize(path)
        if path in self.content_seen and self.content_seen[path] is None:
            return
        if lines is None:
            self.content_seen[path] = None
        else:
            self.content_seen.setdefault(path, set())
            existing = self.content_seen[path]
            if existing is not None:
                existing.update(lines)

    # ------------------------------------------------------------------ dispatch
    def execute(self, name: str, arguments: dict[str, Any] | None) -> ToolResult:
        """Run a tool by name; errors are returned as text instead of raised."""
        start = time.monotonic()
        handler = self._handlers.get(name)
        if handler is None:
            return ToolResult(name, False, f"ERROR: unknown tool {name!r}", 0.0)
        try:
            output = handler(**(arguments or {}))
            ok = True
        except TypeError as exc:
            output, ok = f"ERROR: invalid arguments for {name}: {exc}", False
        except ToolError as exc:
            output, ok = f"ERROR: {exc}", False
        except subprocess.TimeoutExpired:
            output, ok = f"ERROR: {name} timed out", False
        except Exception as exc:  # noqa: BLE001 - tool failures must never crash the agent
            output, ok = f"ERROR: {name} failed unexpectedly: {type(exc).__name__}: {exc}", False
        return ToolResult(name, ok, _truncate(redact(output)), time.monotonic() - start)

    # ------------------------------------------------------------------ tools
    def list_files(self, path: str = ".", max_depth: int | None = None) -> str:
        """List git-tracked files (with sizes) under ``path``."""
        prefix = self.normalize(path)
        if prefix in ("", "."):
            prefix = ""
        files = [f for f in self.tracked_files() if not prefix or f == prefix or f.startswith(prefix + "/")]
        if not files:
            raise ToolError(f"No tracked files under {path!r}")
        if max_depth is not None:
            base = len(PurePosixPath(prefix).parts) if prefix else 0
            files = [f for f in files if len(PurePosixPath(f).parts) - base <= max(1, int(max_depth))]

        lines = [
            f"Repository root listing{' for ' + prefix if prefix else ''} "
            f"(git-tracked files only; default branch: {self.default_branch})",
            f"{len(files)} files shown",
        ]
        limit = 500
        for f in files[:limit]:
            try:
                size = (self.root / f).stat().st_size
            except OSError:
                size = -1
            lines.append(f"{f}  ({size} B)" if size >= 0 else f"{f}  (missing on disk)")
            self.listed_files.add(f)
        if len(files) > limit:
            dirs = Counter(PurePosixPath(f).parts[0] for f in files[limit:])
            lines.append(f"... {len(files) - limit} more files; remaining by top-level directory:")
            lines.extend(f"  {d}/: {n} files" for d, n in dirs.most_common(40))
            lines.append("Use list_files(path=...) to drill into a directory.")
        return "\n".join(lines)

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        """Return file contents with 1-based line numbers (secrets masked)."""
        rel = self.normalize(path)
        text = redact(self._read_text(rel))
        all_lines = text.splitlines()
        total = len(all_lines)
        start = max(1, int(start_line or 1))
        end = total if end_line is None else min(total, int(end_line))
        if end - start + 1 > MAX_READ_LINES:
            end = start + MAX_READ_LINES - 1
        if total == 0:
            self._mark_seen(rel, None)
            return f"{rel}: (empty file)"
        if start > total:
            raise ToolError(f"{rel} has only {total} lines")
        width = len(str(end))
        body = "\n".join(f"{i:>{width}} | {all_lines[i - 1]}" for i in range(start, end + 1))
        self.listed_files.add(rel)
        self._mark_seen(rel, None if (start == 1 and end == total) else set(range(start, end + 1)))
        header = f"{rel} (lines {start}-{end} of {total})"
        if end < total:
            header += f" -- call read_file with start_line={end + 1} for more"
        return header + "\n" + body

    def search_code(
        self,
        pattern: str,
        file_glob: str | None = None,
        ignore_case: bool = False,
        max_results: int = 60,
    ) -> str:
        """Regex search across tracked text files; returns ``file:line: text`` hits."""
        try:
            regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise ToolError(f"Invalid regular expression {pattern!r}: {exc}") from exc
        max_results = max(1, min(int(max_results or 60), 200))
        hits: list[str] = []
        files_with_hits = 0
        total = 0
        for rel in self._text_files(file_glob):
            try:
                text = self._read_text(rel)
            except ToolError:
                continue
            matched_lines = set()
            for lineno, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    total += 1
                    matched_lines.add(lineno)
                    if len(hits) < max_results:
                        hits.append(f"{rel}:{lineno}: {redact(line.strip())[:240]}")
            if matched_lines:
                files_with_hits += 1
                self.listed_files.add(rel)
                self._mark_seen(rel, matched_lines)
        if not hits:
            scope = f" in files matching {file_glob!r}" if file_glob else ""
            return f"No matches for /{pattern}/{scope}."
        summary = f"{total} matches in {files_with_hits} files"
        if total > len(hits):
            summary += f" (showing first {len(hits)})"
        return summary + "\n" + "\n".join(hits)

    def git_log(self, max_count: int = 30, path: str | None = None, show_files: bool = True) -> str:
        """Commit history (newest first), optionally restricted to a path."""
        max_count = max(1, min(int(max_count or 30), 200))
        args = ["log", f"-n{max_count}", "--date=short", "--pretty=format:%h %ad %an | %s"]
        if show_files:
            args.append("--name-status")
        if path:
            args += ["--", self.normalize(path)]
        res = run_git(args, self.root, timeout=self.git_timeout)
        if res.returncode != 0:
            raise ToolError(f"git log failed: {res.stderr.strip() or 'no history available'}")
        count = run_git(["rev-list", "--count", "HEAD"], self.root, timeout=self.git_timeout).stdout.strip()
        out = res.stdout.strip() or "(no commits)"
        return f"Total commits on {self.default_branch}: {count or '?'}\n{out}"

    def git_status(self) -> str:
        """Working-tree status; confirms the audit has not modified the repository."""
        head = run_git(["rev-parse", "--short", "HEAD"], self.root, timeout=self.git_timeout).stdout.strip()
        res = run_git(["status", "--porcelain", "--untracked-files=all"], self.root, timeout=self.git_timeout)
        if res.returncode != 0:
            raise ToolError(f"git status failed: {res.stderr.strip()}")
        state = res.stdout.strip()
        return f"HEAD {head} on {self.default_branch}: " + ("working tree clean" if not state else "\n" + state)

    def scan_secrets(self, include_history: bool = True) -> str:
        """Find likely credentials in tracked files (and optionally git history); values are masked."""
        lines: list[str] = []
        sensitive = []
        for rel in self.tracked_files():
            name = PurePosixPath(rel).name
            if any(fnmatch.fnmatch(name, p) for p in SENSITIVE_EXEMPT):
                continue
            if any(fnmatch.fnmatch(name, p) for p in SENSITIVE_FILENAMES):
                sensitive.append(rel)
                self.listed_files.add(rel)
        lines.append("Sensitive files tracked in git: " + (", ".join(sensitive) if sensitive else "none"))

        current: list[str] = []
        current_keys: set[tuple[str, str]] = set()
        for rel in self.tracked_files():
            try:
                text = self._read_text(rel)
            except ToolError:
                continue
            hits = find_secrets(text)
            if hits:
                self.listed_files.add(rel)
                self._mark_seen(rel, {h.line for h in hits})
            current.extend(f"{rel}:{h.line} [{h.kind}] {h.masked_line}" for h in hits)
            current_keys.update((rel, h.masked_line) for h in hits)
        lines.append(f"Possible secrets in current files: {len(current)}")
        lines.extend("  " + c for c in current[:80])
        if len(current) > 80:
            lines.append(f"  ... {len(current) - 80} more")

        if include_history:
            lines.append(self._scan_history(exclude=current_keys))
        lines.append(
            "Note: hits are heuristic. Check context (test fixtures, documented example keys, "
            "placeholders) before reporting."
        )
        return "\n".join(lines)

    def _scan_history(self, max_commits: int = 300, exclude: set[tuple[str, str]] | None = None) -> str:
        """Secrets added in past commits that are no longer present in the current files."""
        res = run_git(
            ["log", f"-n{max_commits}", "-p", "--no-color", "--unified=0", "--pretty=format:@@commit %h"],
            self.root,
            timeout=self.git_timeout * 2,
        )
        if res.returncode != 0:
            return "Git history scan unavailable: " + res.stderr.strip()[:200]
        tracked = set(self.tracked_files())
        commit, current_file = "?", "?"
        findings: list[str] = []
        seen: set[tuple[str, str]] = set(exclude or ())
        for raw in res.stdout.splitlines():
            if raw.startswith("@@commit "):
                commit = raw.split(" ", 1)[1]
            elif raw.startswith("+++ "):
                current_file = raw[6:] if raw.startswith("+++ b/") else raw[4:]
            elif raw.startswith("+") and not raw.startswith("+++"):
                for hit in find_secrets(raw[1:]):
                    key = (current_file, hit.masked_line)
                    if key in seen:
                        continue
                    seen.add(key)
                    status = "file still tracked" if current_file in tracked else "file no longer tracked"
                    findings.append(f"  commit {commit} {current_file} [{hit.kind}] ({status}) {hit.masked_line}")
        header = (f"Possible secrets in git history no longer present in current files "
                  f"(last {max_commits} commits): {len(findings)}")
        return "\n".join([header, *findings[:60]])

    def inspect_workflows(self) -> str:
        """Parse GitHub Actions workflows and summarise triggers, permissions, jobs and risky patterns."""
        wf_files = [
            f for f in self.tracked_files()
            if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))
        ]
        other_ci = [
            f for f in self.tracked_files()
            if f in {".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "Jenkinsfile", "bitbucket-pipelines.yml",
                     ".circleci/config.yml", ".pre-commit-config.yaml", "tox.ini", "noxfile.py", "Makefile"}
        ]
        out = [f"Default branch: {self.default_branch}"]
        if other_ci:
            out.append("Other CI / automation files present: " + ", ".join(other_ci))
        for extra in (".github/dependabot.yml", ".github/dependabot.yaml", ".github/CODEOWNERS", "CODEOWNERS",
                      ".github/pull_request_template.md", ".github/PULL_REQUEST_TEMPLATE.md"):
            if extra in self.tracked_files():
                out.append(f"Present: {extra}")
        if not wf_files:
            out.append("No GitHub Actions workflows found in .github/workflows/.")
            return "\n".join(out)
        for rel in wf_files:
            out.append("")
            out.extend(self._summarise_workflow(rel))
        out.append(
            "\nNotes: 'observations' are heuristic pointers, not verdicts; read the file to confirm. "
            "Branch protection / required checks live in GitHub settings and cannot be seen from files."
        )
        return "\n".join(out)

    def _summarise_workflow(self, rel: str) -> list[str]:
        text = self._read_text(rel)
        self.listed_files.add(rel)
        self._mark_seen(rel, None)
        out = [f"== {rel} =="]
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = f" at line {mark.line + 1}" if mark else ""
            out.append(f"  INVALID YAML{where}: {str(exc).splitlines()[0]}")
            return out
        if not isinstance(doc, dict):
            out.append("  Workflow is not a mapping; GitHub will reject it.")
            return out
        # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
        triggers = doc.get("on", doc.get(True))
        out.append(f"  name: {doc.get('name', '(unnamed)')}")
        out.append(f"  triggers: {self._fmt_triggers(triggers)}")
        perms = doc.get("permissions", "<not set: falls back to repository/organisation default>")
        out.append(f"  workflow permissions: {perms}")
        if doc.get("env"):
            out.append(f"  workflow env keys: {', '.join(map(str, doc['env'].keys()))}")
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict) or not jobs:
            out.append("  jobs: none defined")
        for job_id, job in (jobs.items() if isinstance(jobs, dict) else []):
            if not isinstance(job, dict):
                continue
            meta = [f"runs-on={job.get('runs-on', job.get('uses', '?'))}"]
            for key in ("needs", "if", "permissions", "environment", "continue-on-error", "timeout-minutes"):
                if key in job:
                    meta.append(f"{key}={job[key]}")
            if job.get("strategy"):
                meta.append("matrix" if "matrix" in job["strategy"] else "strategy")
            out.append(f"  job {job_id}: " + "; ".join(meta))
            for i, step in enumerate(job.get("steps") or [], start=1):
                if not isinstance(step, dict):
                    continue
                label = step.get("name", "")
                if "uses" in step:
                    desc = f"uses {step['uses']}"
                else:
                    run = str(step.get("run", "")).strip().replace("\n", " ; ")
                    desc = f"run: {run[:200]}"
                flags = [f"{k}={step[k]}" for k in ("if", "continue-on-error") if k in step]
                out.append(f"    step {i}{' [' + label + ']' if label else ''}: {desc}" + (f"  ({', '.join(flags)})" if flags else ""))
        obs = self._workflow_observations(text, triggers)
        if obs:
            out.append("  observations:")
            out.extend(f"    - {o}" for o in obs)
        return out

    @staticmethod
    def _fmt_triggers(triggers: Any) -> str:
        if triggers is None:
            return "NONE (workflow will never run)"
        if isinstance(triggers, (str, list)):
            return json.dumps(triggers)
        if isinstance(triggers, dict):
            parts = []
            for event, cfg in triggers.items():
                if isinstance(cfg, dict) and cfg:
                    filt = ", ".join(f"{k}={v}" for k, v in cfg.items())
                    parts.append(f"{event}({filt})")
                else:
                    parts.append(str(event))
            return "; ".join(parts)
        return str(triggers)

    def _workflow_observations(self, text: str, triggers: Any) -> list[str]:
        checks = [
            (r"pull_request_target", "uses pull_request_target (runs with base-repo secrets; dangerous if PR code is checked out/executed)"),
            (r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", "checks out pull-request head code"),
            (r"continue-on-error:\s*true", "continue-on-error: true (failures will not fail the job)"),
            (r"\|\|\s*(true|exit 0|:)\s*$", "command failure masked with `|| true`/`|| exit 0`"),
            (r"^\s*if:\s*(false|\$\{\{\s*false\s*\}\})", "step/job disabled with if: false"),
            (r"permissions:\s*write-all", "permissions: write-all"),
            (r"^\s*(contents|packages|actions|pull-requests|id-token|deployments|security-events):\s*write", "write permission granted"),
            (r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|head_commit|commits)[^}]*\.(title|body|message|name|email|label|ref)|head_ref)[^}]*\}\}",
             "untrusted github context interpolated (possible script injection if used in run:)"),
            (r"uses:\s*[^\s@#]+@(master|main|HEAD|latest)\b", "action referenced by mutable branch (@master/@main)"),
            (r"uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+\s*$", "action referenced without any version"),
            (r"(echo|printf|cat).*\$\{\{\s*secrets\.", "secret printed in a run step"),
            (r"curl[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh", "pipes a downloaded script into a shell"),
            (r"ACTIONS_ALLOW_UNSECURE_COMMANDS", "re-enables insecure workflow commands"),
            (r"--no-verify|--skip-tests|-DskipTests|--passWithNoTests|SKIP_TESTS", "validation explicitly skipped"),
            (r"actions/checkout@v[12]\b|actions/setup-python@v[1-3]\b|actions/setup-node@v[1-2]\b|ubuntu-(16|18|20)\.04|::set-output", "deprecated action/runner/command"),
        ]
        obs = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            for pattern, message in checks:
                if re.search(pattern, line):
                    obs.append(f"line {lineno}: {message}: `{redact(line.strip())[:160]}`")
        branches = self._trigger_branches(triggers)
        if branches and self.default_branch not in ("unknown", "") and not any(
            fnmatch.fnmatch(self.default_branch, b) for b in branches
        ):
            obs.append(
                f"branch filters {sorted(branches)} do not include the default branch '{self.default_branch}'"
            )
        if not re.search(r"\b(pytest|unittest|tox|nox|npm (run )?test|yarn test|pnpm test|go test|cargo test|mvn|gradle|make test|jest|vitest)\b", text):
            obs.append("no recognisable test command in this workflow")
        return obs

    @staticmethod
    def _trigger_branches(triggers: Any) -> set[str]:
        branches: set[str] = set()
        if isinstance(triggers, dict):
            for event in ("push", "pull_request"):
                cfg = triggers.get(event)
                if isinstance(cfg, dict) and isinstance(cfg.get("branches"), list):
                    branches.update(str(b) for b in cfg["branches"])
        return branches

    def inspect_dependencies(self) -> str:
        """Locate dependency manifests and lockfiles and classify version constraints."""
        files = self.tracked_files()
        manifest_patterns = [
            "requirements*.txt", "requirements*.in", "requirements/*.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "Pipfile", "environment.yml", "environment.yaml", "package.json", "go.mod", "Cargo.toml", "Gemfile",
            "pom.xml", "build.gradle", "build.gradle.kts", "composer.json",
        ]
        lock_patterns = [
            "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements*.lock", "conda-lock.yml",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
        ]

        def match(patterns: list[str]) -> list[str]:
            res = []
            for f in files:
                if any(part in SKIP_DIRS for part in PurePosixPath(f).parts):
                    continue
                name = PurePosixPath(f).name
                if any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(f, p) for p in patterns):
                    res.append(f)
            return res

        manifests, locks = match(manifest_patterns), match(lock_patterns)
        out = [
            "Manifests: " + (", ".join(manifests) if manifests else "none found"),
            "Lockfiles: " + (", ".join(locks) if locks else "none found"),
        ]
        declared: dict[str, dict[str, str]] = {}
        for rel in manifests:
            self.listed_files.add(rel)
            try:
                text = self._read_text(rel)
            except ToolError as exc:
                out.append(f"\n{rel}: {exc}")
                continue
            self._mark_seen(rel, None)
            name = PurePosixPath(rel).name
            out.append(f"\n== {rel} ==")
            if name.endswith((".txt", ".in")):
                out.extend(self._analyse_requirements(text, declared.setdefault(rel, {})))
            elif name == "pyproject.toml":
                out.extend(self._analyse_pyproject(text, declared.setdefault(rel, {})))
            elif name == "package.json":
                out.extend(self._analyse_package_json(text))
            elif name == "setup.py":
                found = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.DOTALL)
                reqs = re.findall(r"[\"']([^\"']+)[\"']", found.group(1)) if found else []
                out.append(f"  install_requires: {reqs if reqs else 'not found statically'}")
            else:
                out.append(f"  ({len(text.splitlines())} lines; read_file for details)")

        # Cross-manifest consistency for Python packages.
        by_pkg: dict[str, set[str]] = {}
        for specs in declared.values():
            for pkg, spec in specs.items():
                by_pkg.setdefault(pkg, set()).add(spec or "(unconstrained)")
        conflicts = {p: s for p, s in by_pkg.items() if len(s) > 1}
        if conflicts:
            out.append("\nInconsistent specifications across manifests:")
            out.extend(f"  {p}: {sorted(s)}" for p, s in sorted(conflicts.items()))
        out.append(
            "\nNotes: exact pins (==) in requirements.txt act as a lock for applications; libraries "
            "normally use ranges and need not commit lockfiles. poetry/pipenv/uv/npm/yarn projects that are "
            "applications are expected to commit their lockfile."
        )
        return "\n".join(out)

    @staticmethod
    def _split_requirement(req: str) -> tuple[str, str]:
        req = req.split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", req)
        if not m:
            return req, ""
        return m.group(1).lower().replace("_", "-"), m.group(3).strip()

    def _classify(self, spec: str) -> str:
        if not spec:
            return "UNPINNED"
        if spec.startswith("==") and "*" not in spec:
            return "pinned"
        if spec.startswith("~=") or ("<" in spec and ">" in spec):
            return "bounded range"
        if spec.startswith((">=", ">")):
            return "lower-bound only"
        return "constrained"

    def _analyse_requirements(self, text: str, declared: dict[str, str]) -> list[str]:
        out, counts = [], Counter()
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.split(" #")[0].strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "-c", "--requirement", "--constraint")):
                out.append(f"  line {lineno}: include {line}")
                continue
            if line.startswith(("--index-url", "-i ", "--extra-index-url", "--trusted-host", "-f", "--find-links")):
                out.append(f"  line {lineno}: index option `{line}`" + ("  <-- insecure http" if "http://" in line else ""))
                continue
            if line.startswith(("-e", "git+", "http")) or "@" in line:
                out.append(f"  line {lineno}: direct/VCS reference `{line}`")
                counts["direct"] += 1
                continue
            pkg, spec = self._split_requirement(line)
            declared[pkg] = spec
            cls = self._classify(spec)
            counts[cls] += 1
            out.append(f"  line {lineno}: {pkg} {spec or ''} -> {cls}")
        out.insert(0, "  summary: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
        return out

    def _analyse_pyproject(self, text: str, declared: dict[str, str]) -> list[str]:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            return [f"  INVALID TOML: {exc}"]
        out = []
        project = data.get("project", {})
        tool = data.get("tool", {})
        build = data.get("build-system", {})
        out.append(f"  build-system: {build.get('build-backend', 'not declared')}")
        if project:
            out.append(f"  project: name={project.get('name')} version={project.get('version', 'dynamic' if 'version' in project.get('dynamic', []) else None)} requires-python={project.get('requires-python')}")
            for dep in project.get("dependencies", []):
                pkg, spec = self._split_requirement(dep)
                declared[pkg] = spec
                out.append(f"  dependency: {pkg} {spec} -> {self._classify(spec)}")
            for group, deps in (project.get("optional-dependencies") or {}).items():
                out.append(f"  optional[{group}]: {', '.join(deps)}")
        poetry = tool.get("poetry", {})
        if poetry:
            for pkg, spec in (poetry.get("dependencies") or {}).items():
                spec_s = spec if isinstance(spec, str) else json.dumps(spec)
                out.append(f"  poetry dependency: {pkg} {spec_s}" + ("  <-- wildcard" if spec_s.strip() == "*" else ""))
        tools = sorted(k for k in tool if k in {"ruff", "black", "isort", "flake8", "pylint", "mypy", "pytest", "coverage", "poetry", "uv", "pdm", "hatch", "setuptools"})
        out.append(f"  [tool.*] sections: {', '.join(tools) if tools else 'none'}")
        return out

    @staticmethod
    def _analyse_package_json(text: str) -> list[str]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [f"  INVALID JSON: {exc}"]
        out = [f"  scripts: {', '.join((data.get('scripts') or {}).keys()) or 'none'}"]
        for section in ("dependencies", "devDependencies"):
            for pkg, spec in (data.get(section) or {}).items():
                flag = "  <-- unbounded" if spec in ("*", "latest", "") or spec.startswith(">=") else ""
                out.append(f"  {section}: {pkg} {spec}{flag}")
        return out

    def run_ruff(self, path: str = ".") -> str:
        """Run the Ruff linter (static analysis only; never imports or executes repo code)."""
        target = self._resolve(path)
        exe = shutil.which("ruff")
        cmd = [exe] if exe else [sys.executable, "-m", "ruff"]
        cmd += ["check", "--no-cache", "--exit-zero", "--output-format=concise", "--force-exclude", str(target)]
        try:
            res = subprocess.run(cmd, cwd=str(self.root), capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=120, check=False)
        except FileNotFoundError as exc:
            raise ToolError("ruff is not installed; this check is unavailable") from exc
        if res.returncode != 0 and "No module named ruff" in (res.stderr or ""):
            raise ToolError("ruff is not installed; this check is unavailable")
        lines = []
        for ln in res.stdout.splitlines():
            if not ln.strip():
                continue
            ln = ln.replace(str(self.root) + "\\", "").replace(str(self.root) + "/", "")
            path, sep, rest = ln.partition(":")
            lines.append(path.replace("\\", "/") + sep + rest)  # POSIX paths on every OS
        issues = [ln for ln in lines if re.match(r"^.+?:\d+:\d+: [A-Z]+\d+", ln)]
        if not issues:
            tail = (res.stderr or "").strip().splitlines()[-1:] if res.stderr else []
            return "ruff: no issues found" + (f" ({tail[0]})" if tail else "")
        codes = Counter(re.search(r": ([A-Z]+\d+)", ln).group(1) for ln in issues)
        for ln in issues[:80]:
            m = re.match(r"^(.+?):(\d+):", ln)
            if m:
                self._mark_seen(m.group(1).replace("\\", "/"), {int(m.group(2))})
        config = [f for f in self.tracked_files() if PurePosixPath(f).name in {"ruff.toml", ".ruff.toml", "pyproject.toml"}]
        return "\n".join([
            f"ruff: {len(issues)} issues; by rule: " + ", ".join(f"{c}={n}" for c, n in codes.most_common(20)),
            "(uses the repository's ruff config if present, otherwise ruff defaults: pyflakes F + pycodestyle E subset; "
            f"config candidates: {', '.join(config) or 'none'})",
            *issues[:80],
        ])


# ---------------------------------------------------------------------- schemas
def _fn(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required or []},
        },
    }


TOOL_SCHEMAS: list[dict[str, Any]] = [
    _fn("list_files", "List git-tracked files with sizes. Use to discover structure, then drill into directories.",
        {"path": {"type": "string", "description": "Directory relative to repo root (default '.')."},
         "max_depth": {"type": "integer", "description": "Optional maximum depth below path."}}),
    _fn("read_file", "Read a text file with 1-based line numbers (max 400 lines per call; secrets are masked).",
        {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
        ["path"]),
    _fn("search_code", "Regex search over tracked text files. Returns file:line: text for each match.",
        {"pattern": {"type": "string", "description": "Python regular expression."},
         "file_glob": {"type": "string", "description": "Optional comma-separated globs, e.g. '*.py,*.yml'."},
         "ignore_case": {"type": "boolean"},
         "max_results": {"type": "integer"}},
        ["pattern"]),
    _fn("git_log", "Show commit history with changed files (name-status).",
        {"max_count": {"type": "integer"}, "path": {"type": "string", "description": "Optional path filter."},
         "show_files": {"type": "boolean"}}),
    _fn("inspect_workflows", "Parse every GitHub Actions workflow: triggers, permissions, jobs, steps, and heuristic "
        "risk observations with line numbers. Also lists other CI files, dependabot, CODEOWNERS.", {}),
    _fn("inspect_dependencies", "Find dependency manifests and lockfiles, classify version constraints and report "
        "inconsistencies between manifests.", {}),
    _fn("scan_secrets", "Scan tracked files (and optionally git history) for credentials and sensitive files. "
        "Values are always masked.",
        {"include_history": {"type": "boolean", "description": "Also scan added lines in recent commits (default true)."}}),
    _fn("run_ruff", "Run the Ruff linter statically on Python code (never executes repository code).",
        {"path": {"type": "string", "description": "Path to lint (default '.')."}}),
    _fn("git_status", "Show HEAD and working-tree status (verifies the audit left the repository unchanged).", {}),
]
