"""Secret detection and masking.

Every piece of text that leaves a tool (and therefore reaches the LLM, the trace
log, or the final report) passes through :func:`redact`. Secret values are
replaced by a marker such as ``[REDACTED:aws_access_key_id]`` so the agent can
still reason about *where* a credential is and *what kind* it is without ever
seeing or reproducing the value.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# High-confidence, provider-specific token formats.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "url_credentials",
        re.compile(r"(?<=://)[^\s:/@'\"]{1,64}:[^\s:/@'\"]{3,128}(?=@[\w.-]+)"),
    ),
]

PRIVATE_KEY_BLOCK = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.*?)(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
    re.DOTALL,
)
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

# Names that suggest the assigned value is a credential.
_SECRET_NAME = (
    r"[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?|signing[_-]?key)[A-Za-z0-9_.-]*"
)

# `name = "value"` / `name: 'value'` / `"name": "value"` with a quoted literal.
QUOTED_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>[\"']?" + _SECRET_NAME + r"[\"']?)(?P<sep>\s*(?::=|=>|[:=])\s*)"
    r"(?P<q>[\"'])(?P<value>[^\"'\n]{4,})(?P=q)"
)

# dotenv / ini / yaml style `NAME=value` on its own line with an unquoted value.
UNQUOTED_ASSIGNMENT = re.compile(
    r"(?im)^(?P<prefix>\s*(?:export\s+)?)(?P<name>" + _SECRET_NAME + r")(?P<sep>\s*[:=]\s*)"
    r"(?P<value>[^\s'\"#]{4,})\s*$"
)

_PLACEHOLDER = re.compile(
    r"(?ix)^(?:"
    r"\$\{.*\}|\$\{\{.*\}\}|\$[A-Z_][A-Z0-9_]*|%\(?[A-Za-z_]+\)?s?%?|\{\{.*\}\}|<.*>"
    r"|your[_-].*|changeme|change[_-]?me|example.*|dummy.*|placeholder.*|redacted.*|todo"
    r"|x{3,}|\*{3,}|\.{3,}|none|null|nil|true|false|undefined|test|testing|secret|password"
    r"|\[REDACTED.*\]"
    r")$"
)
_CODE_LIKE = re.compile(r"[()\[\]{}]|os\.|getenv|environ|process\.env|config\.|settings\.")


@dataclass(frozen=True)
class SecretHit:
    """A detected secret in a single line (value never stored)."""

    line: int
    kind: str
    masked_line: str


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_DOCUMENTED_EXAMPLE = re.compile(r"EXAMPLE|example|DUMMY|dummy|FAKE|fake|0{8,}|x{8,}|X{8,}")


def is_documented_example(value: str) -> bool:
    """Publicly documented dummy credentials (e.g. AWS's AKIAIOSFODNN7EXAMPLE) are not secrets."""
    return bool(_DOCUMENTED_EXAMPLE.search(value))


def is_placeholder(value: str) -> bool:
    """True for values that are clearly references or dummies, not real secrets."""
    value = value.strip()
    if not value or _PLACEHOLDER.match(value) or _CODE_LIKE.search(value) or is_documented_example(value):
        return True
    if re.fullmatch(r"[\d.]+", value):  # numbers such as timeouts / TTLs
        return True
    return False


def _mask_generic(match: re.Match[str]) -> str:
    value = match.group("value")
    if is_placeholder(value):
        return match.group(0)
    masked = f"[REDACTED:len={len(value)}]"
    start, end = match.span("value")
    offset = match.start()
    whole = match.group(0)
    return whole[: start - offset] + masked + whole[end - offset :]


def redact(text: str) -> str:
    """Mask every secret-looking value in ``text`` while preserving line structure."""
    if not text:
        return text

    def _mask_key_block(m: re.Match[str]) -> str:
        body = re.sub(r"[^\n]+", "[REDACTED:private_key]", m.group(2))
        return m.group(1) + body + m.group(3)

    text = PRIVATE_KEY_BLOCK.sub(_mask_key_block, text)
    for kind, pattern in SECRET_PATTERNS:
        text = pattern.sub(
            lambda m, k=kind: m.group(0) if is_documented_example(m.group(0)) else f"[REDACTED:{k}]", text
        )
    text = QUOTED_ASSIGNMENT.sub(_mask_generic, text)
    text = UNQUOTED_ASSIGNMENT.sub(_mask_generic, text)
    return text


def find_secrets(text: str) -> list[SecretHit]:
    """Return one hit per line that contains a likely secret.

    Generic ``name = "value"`` assignments are only reported when the value is
    not a placeholder and has some randomness, which keeps false positives low.
    """
    hits: list[SecretHit] = []
    in_key_block = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        kind: str | None = None
        if PRIVATE_KEY_HEADER.search(line):
            kind = "private_key"
            in_key_block = True
        elif in_key_block:
            if "-----END" in line:
                in_key_block = False
            continue
        if kind is None:
            for name, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    example = is_documented_example(match.group(0))
                    kind = f"{name} (documented example/dummy value)" if example else name
                    break
        if kind is None:
            for pattern in (QUOTED_ASSIGNMENT, UNQUOTED_ASSIGNMENT):
                for m in pattern.finditer(line):
                    value = m.group("value")
                    if is_placeholder(value):
                        continue
                    if len(value) >= 6 and shannon_entropy(value) >= 2.5:
                        kind = "hardcoded_credential"
                        break
                if kind:
                    break
        if kind:
            hits.append(SecretHit(lineno, kind, redact(line).strip()[:200]))
    return hits
