"""Safe acquisition of the repository under audit.

The target is cloned into a fresh temporary directory. Nothing from the
repository is executed: git hooks are never cloned, submodules are not
initialised, Git LFS smudging is disabled and git never prompts for credentials
(so private or non-existent repositories fail fast instead of hanging).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

GITHUB_URL = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<name>[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$"
)


class RepoError(Exception):
    """The repository could not be validated, cloned or inspected."""


class InvalidRepoURL(RepoError):
    """The supplied repository URL is not a public GitHub repository URL."""


def normalize_github_url(url: str) -> str:
    """Validate a GitHub URL and return its canonical ``https://github.com/owner/name`` form."""
    url = (url or "").strip()
    match = GITHUB_URL.match(url)
    if not match or match.group("name") in {".", ".."}:
        raise InvalidRepoURL(
            f"Not a valid GitHub repository URL: {url!r}. "
            "Expected the form https://github.com/<owner>/<repository>"
        )
    return f"https://github.com/{match.group('owner')}/{match.group('name')}"


def git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",  # never block on a credential prompt
            "GIT_LFS_SKIP_SMUDGE": "1",  # do not download LFS objects
            "GIT_ASKPASS": "echo",
            "GCM_INTERACTIVE": "never",
        }
    )
    return env


def run_git(args: list[str], cwd: Path | None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run git with a timeout and a non-interactive environment."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            env=git_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RepoError("git executable not found; install Git and make sure it is on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepoError(f"git {' '.join(args[:2])} timed out after {timeout}s") from exc


@dataclass
class Workspace:
    """A local checkout of the repository being audited."""

    url: str
    path: Path
    temporary: bool = True
    default_branch: str = "unknown"
    head_commit: str = "unknown"
    commit_count: int = 0
    initial_state: str = field(default="", repr=False)

    def snapshot(self) -> str:
        """Fingerprint of HEAD + working-tree status, used to prove the audit changed nothing."""
        head = run_git(["rev-parse", "HEAD"], self.path).stdout.strip()
        status = run_git(["status", "--porcelain", "--untracked-files=all"], self.path).stdout
        return f"{head}\n{status}"

    def verify_unchanged(self) -> bool:
        return self.snapshot() == self.initial_state

    def cleanup(self) -> None:
        if self.temporary and self.path.exists():
            shutil.rmtree(self.path, onerror=_force_remove)


def _force_remove(func, path, _exc_info):  # pragma: no cover - Windows read-only git objects
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _describe(ws: Workspace) -> Workspace:
    branch = run_git(["symbolic-ref", "--short", "HEAD"], ws.path)
    ws.default_branch = branch.stdout.strip() or "unknown"
    head = run_git(["rev-parse", "--short", "HEAD"], ws.path)
    ws.head_commit = head.stdout.strip() or "unknown"
    count = run_git(["rev-list", "--count", "HEAD"], ws.path)
    ws.commit_count = int(count.stdout.strip()) if count.stdout.strip().isdigit() else 0
    ws.initial_state = ws.snapshot()
    return ws


def clone_repository(url: str, timeout: int = 300) -> Workspace:
    """Clone a public GitHub repository into a new temporary directory."""
    canonical = normalize_github_url(url)
    target = Path(tempfile.mkdtemp(prefix="devops-audit-"))
    result = run_git(
        [
            "-c", "core.symlinks=false",
            "-c", "protocol.file.allow=never",
            "clone", "--quiet", "--no-tags", "--single-branch",
            canonical + ".git", str(target / "repo"),
        ],
        cwd=None,
        timeout=timeout,
    )
    if result.returncode != 0:
        shutil.rmtree(target, onerror=_force_remove)
        detail = (result.stderr or result.stdout).strip().splitlines()
        hint = detail[-1] if detail else "unknown error"
        raise RepoError(
            f"Could not clone {canonical}: {hint}. "
            "Check that the repository exists and is public."
        )
    ws = Workspace(url=canonical, path=target / "repo", temporary=True)
    # Clean up the parent temp dir too.
    ws_cleanup = ws.cleanup

    def cleanup() -> None:
        ws_cleanup()
        shutil.rmtree(target, ignore_errors=True)

    ws.cleanup = cleanup  # type: ignore[method-assign]
    return _describe(ws)


def open_local_repository(path: str | Path, url: str | None = None) -> Workspace:
    """Use an existing local git checkout (read-only); intended for tests and offline evaluation."""
    p = Path(path).resolve()
    if not (p / ".git").exists():
        raise RepoError(f"{p} is not a git repository")
    return _describe(Workspace(url=url or p.as_uri(), path=p, temporary=False))
