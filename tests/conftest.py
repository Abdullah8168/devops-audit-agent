"""Shared fixtures: throwaway git repositories and a scripted fake LLM."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auditor.llm import LLMResponse, ToolCall  # noqa: E402


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    return result.stdout


def make_repo(root: Path, files: dict[str, str | bytes], message: str = "initial commit") -> Path:
    """Create a git repo on branch main containing ``files`` in a single commit."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", "-b", "main")
    add_commit(root, files, message)
    return root


def add_commit(root: Path, files: dict[str, str | bytes | None], message: str) -> None:
    """Write (or delete, when the value is None) files and commit them."""
    for rel, content in files.items():
        path = root / rel
        if content is None:
            git(root, "rm", "-q", rel)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)


@pytest.fixture
def repo_factory(tmp_path: Path):
    counter = {"n": 0}

    def factory(files: dict[str, str | bytes], message: str = "initial commit") -> Path:
        counter["n"] += 1
        return make_repo(tmp_path / f"repo{counter['n']}", files, message)

    return factory


class FakeLLM:
    """Replays scripted turns. Each turn is a list of (tool_name, arguments) or a text string."""

    model = "fake-model"

    def __init__(self, turns: list[Any]):
        self.turns = list(turns)
        self.calls: list[dict[str, Any]] = []
        self.total_usage = {"requests": 0}

    def chat(self, messages, tools, tool_choice="auto") -> LLMResponse:
        self.calls.append({"messages": [dict(m) for m in messages], "tools": [t["function"]["name"] for t in tools]})
        self.total_usage["requests"] += 1
        turn = self.turns.pop(0) if self.turns else "I have nothing more to add."
        if isinstance(turn, str):
            return LLMResponse(content=turn, tool_calls=[], message={"role": "assistant", "content": turn})
        calls = []
        for i, (name, args) in enumerate(turn):
            raw = args if isinstance(args, str) else json.dumps(args)
            parse_error = None
            parsed = args if isinstance(args, dict) else {}
            if isinstance(args, str):
                try:
                    parsed = json.loads(args)
                except json.JSONDecodeError as exc:
                    parse_error = str(exc)
            calls.append(ToolCall(id=f"c{len(self.calls)}_{i}", name=name, arguments=parsed,
                                  raw_arguments=raw, parse_error=parse_error))
        message = {
            "role": "assistant",
            "content": "checking",
            "tool_calls": [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.raw_arguments}}
                for c in calls
            ],
        }
        return LLMResponse(content="checking", tool_calls=calls, message=message)


def violation(**overrides: Any) -> dict[str, Any]:
    base = {
        "rule_id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "file": "config.py",
        "line": 2,
        "description": "Hardcoded API credential",
        "evidence": "API_KEY assigned a literal in config.py",
        "recommendation": "Load the key from an environment variable or secrets manager",
    }
    base.update(overrides)
    return base
