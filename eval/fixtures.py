"""Synthetic evaluation repositories with known, injected DevOps defects.

Each fixture is a sequence of commits (``{path: content}``, ``None`` deletes a
file) plus an answer key. They mirror the three hidden-repository types in the
assignment: (A) obvious issues, (B) subtle CI/security/configuration defects,
and (C) a mostly healthy repository used to measure false positives.

Fake credentials are assembled at runtime so this source file contains no
literal secrets (and does not trip secret scanners or push protection).
"""

from __future__ import annotations

from typing import Any

_FAKE_AWS = "AKIA" + "Q3EGRTZXMPLW7Y2B"
_FAKE_SECRET = "f9" + "Kq2LmZx8WvB3nT7pR4sYc1"
_FAKE_DB_PW = "Pr0d" + "-db-P4ss!2024"
_FAKE_DEPLOY = "dpl_" + "7hG2kLq9ZxW4mN8vB3cT6yR1"

# --------------------------------------------------------------------------- A
FIXTURE_A: dict[str, Any] = {
    "name": "fixture-a-obvious",
    "commits": [
        {
            "message": "initial inventory api",
            "files": {
                "app.py": (
                    "from flask import Flask, jsonify\n"
                    "import psycopg2\n"
                    "from config import DATABASE_URL, SECRET_KEY\n\n"
                    "app = Flask(__name__)\n"
                    "app.config['SECRET_KEY'] = SECRET_KEY\n\n\n"
                    "@app.route('/items')\n"
                    "def items():\n"
                    "    conn = psycopg2.connect(DATABASE_URL)\n"
                    "    cur = conn.cursor()\n"
                    "    cur.execute('SELECT id, name FROM items')\n"
                    "    return jsonify(cur.fetchall())\n\n\n"
                    "if __name__ == '__main__':\n"
                    "    app.run(host='0.0.0.0', debug=True)\n"
                ),
                "config.py": (
                    "# Application configuration\n"
                    f"SECRET_KEY = \"{_FAKE_SECRET}\"\n"
                    f"DATABASE_URL = \"postgresql://admin:{_FAKE_DB_PW}@10.0.0.12:5432/inventory\"\n"
                    f"AWS_ACCESS_KEY_ID = \"{_FAKE_AWS}\"\n"
                ),
                ".env": f"FLASK_ENV=production\nDB_PASSWORD={_FAKE_DB_PW}\nSECRET_KEY={_FAKE_SECRET}\n",
                "requirements.txt": "flask\npsycopg2\nrequests\n",
                "__pycache__/config.cpython-311.pyc": b"\xa7\r\r\n\x00\x00\x00\x00fake-bytecode",
                "__pycache__/app.cpython-311.pyc": b"\xa7\r\r\n\x00\x00\x00\x00fake-bytecode",
                "server.log": "2024-01-01 12:00:00 INFO started\n2024-01-01 12:00:05 INFO GET /items 200\n",
            },
        }
    ],
    # Each expected violation lists acceptable rule IDs (alternatives) and the file (None = any location,
    # a list = any of these locations, e.g. one root cause visible in several files).
    "expected": [
        {"id": "A1", "rule_ids": ["HYG-001"], "file": None, "what": "README missing"},
        {"id": "A2", "rule_ids": ["HYG-002", "HYG-003"], "file": None, "what": ".gitignore missing"},
        {"id": "A3", "rule_ids": ["HYG-004"], "file": ["__pycache__", "server.log"], "what": "bytecode/log files tracked"},
        {"id": "A4", "rule_ids": ["SEC-003", "SEC-001"], "file": ".env", "what": ".env committed"},
        {"id": "A5", "rule_ids": ["SEC-001"], "file": "config.py", "what": "hardcoded credentials in config.py"},
        {"id": "A6", "rule_ids": ["DEP-002", "DEP-004"], "file": "requirements.txt", "what": "unpinned dependencies"},
        {"id": "A7", "rule_ids": ["TST-001"], "file": None, "what": "no tests"},
        {"id": "A8", "rule_ids": ["CI-001"], "file": None, "what": "no CI"},
    ],
    # Findings that are defensible but not part of the answer key: neither rewarded nor penalised.
    "acceptable": [
        {"rule_ids": ["SEC-008", "CFG-003"], "file": "app.py"},
        {"rule_ids": ["CQ-001"], "file": None},
        # The fixture app genuinely never closes its DB connection (a real, if unplanned, defect).
        {"rule_ids": ["CQ-003"], "file": "app.py"},
        {"rule_ids": ["CFG-003", "CFG-004"], "file": None},
        # Hardcoded DB host IP: an environment-separation issue; models label it CFG-001 or CFG-003.
        {"rule_ids": ["CFG-003", "CFG-001", "SEC-001"], "file": "config.py"},
    ],
}

# --------------------------------------------------------------------------- B
_B_README = """\
# metrics-service

Small HTTP service that aggregates application metrics.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
ruff check . && pytest
```

Configuration is read from environment variables (see `.env.example`).
"""

_B_CI = """\
name: CI

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: ruff check .
      - name: Run tests
        run: pytest -q || true
"""

_B_PREVIEW = """\
name: PR preview

on:
  pull_request_target:
    types: [opened, synchronize]

permissions: write-all

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Announce
        run: echo "Building preview for ${{ github.event.pull_request.title }}"
      - name: Build and publish preview
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          pip install -r requirements.txt
          python scripts/publish_preview.py
"""

FIXTURE_B: dict[str, Any] = {
    "name": "fixture-b-subtle",
    "commits": [
        {
            "message": "initial service",
            "files": {
                "README.md": _B_README,
                ".gitignore": "__pycache__/\n*.pyc\n.venv/\n.env\n.pytest_cache/\n",
                ".env.example": "METRICS_DB_URL=\nMETRICS_API_TOKEN=\n",
                "pyproject.toml": (
                    "[project]\nname = \"metrics-service\"\nversion = \"0.3.0\"\nrequires-python = \">=3.10\"\n"
                    "dependencies = [\"requests>=2.20,<2.30\", \"fastapi==0.110.0\"]\n\n"
                    "[tool.ruff]\nline-length = 100\n\n[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n"
                ),
                "requirements.txt": "fastapi==0.110.0\nrequests==2.31.0\nuvicorn==0.29.0\n",
                "requirements-dev.txt": "pytest==8.1.1\nruff==0.4.1\n",
                "metrics/__init__.py": "",
                "metrics/settings.py": (
                    "import os\n\n"
                    "DB_URL = os.environ.get(\"METRICS_DB_URL\", \"sqlite:///metrics.db\")\n"
                    "API_TOKEN = os.environ[\"METRICS_API_TOKEN\"]\n"
                    "DATA_DIR = \"C:/Users/jdoe/projects/metrics/data\"\n"
                    "EXPORT_PATH = os.path.join(DATA_DIR, \"exports\")\n"
                ),
                "metrics/aggregate.py": (
                    "from statistics import mean\n\n\n"
                    "def summarize(values: list[float]) -> dict[str, float]:\n"
                    "    if not values:\n"
                    "        return {\"count\": 0, \"mean\": 0.0}\n"
                    "    return {\"count\": len(values), \"mean\": mean(values)}\n"
                ),
                "scripts/publish_preview.py": "import os\n\nprint('publishing preview', bool(os.environ.get('DEPLOY_TOKEN')))\n",
                "tests/test_aggregate.py": (
                    "from metrics.aggregate import summarize\n\n\n"
                    "def test_empty():\n    assert summarize([]) == {\"count\": 0, \"mean\": 0.0}\n\n\n"
                    "def test_mean():\n    assert summarize([1.0, 3.0])[\"mean\"] == 2.0\n"
                ),
                ".github/workflows/ci.yml": _B_CI,
                ".github/workflows/preview.yml": _B_PREVIEW,
                ".vscode/settings.json": (
                    "{\n  \"python.defaultInterpreterPath\": \"C:\\\\Users\\\\jdoe\\\\envs\\\\metrics\\\\python.exe\",\n"
                    "  \"editor.formatOnSave\": true\n}\n"
                ),
            },
        },
        {
            "message": "add deploy helper",
            "files": {"scripts/deploy.sh": f"#!/bin/sh\nDEPLOY_TOKEN=\"{_FAKE_DEPLOY}\"\ncurl -H \"Authorization: $DEPLOY_TOKEN\" https://deploy.example.com\n"},
        },
        {
            "message": "remove deploy helper",
            "files": {"scripts/deploy.sh": None},
        },
    ],
    "expected": [
        {"id": "B1", "rule_ids": ["CI-002"], "file": ".github/workflows/ci.yml", "what": "CI triggers on master; default branch is main"},
        {"id": "B2", "rule_ids": ["CI-003", "TST-003"], "file": ".github/workflows/ci.yml", "what": "pytest failures masked with || true"},
        {"id": "B3", "rule_ids": ["SEC-005"], "file": ".github/workflows/preview.yml", "what": "pull_request_target runs PR head code with secrets"},
        {"id": "B4", "rule_ids": ["SEC-004"], "file": ".github/workflows/preview.yml", "what": "permissions: write-all"},
        {"id": "B5", "rule_ids": ["SEC-006"], "file": ".github/workflows/preview.yml", "what": "PR title interpolated into run"},
        {"id": "B6", "rule_ids": ["CFG-001"], "file": "metrics/settings.py", "what": "machine-specific absolute path"},
        {"id": "B7", "rule_ids": ["CFG-002", "CFG-001"], "file": ".vscode/settings.json", "what": "committed IDE settings with local path"},
        {"id": "B8", "rule_ids": ["SEC-002"], "file": "scripts/deploy.sh", "what": "token committed in history"},
        {"id": "B9", "rule_ids": ["DEP-003"], "file": None, "what": "requests version conflicts between pyproject and requirements"},
    ],
    "acceptable": [
        {"rule_ids": ["DEP-003", "DEP-002"], "file": "requirements.txt"},
        {"rule_ids": ["DEP-003", "DEP-002"], "file": "pyproject.toml"},
        {"rule_ids": ["BLD-002", "BLD-003", "SEC-007"], "file": ".github/workflows/preview.yml"},
        {"rule_ids": ["TST-002"], "file": ".github/workflows/ci.yml"},
    ],
}

# --------------------------------------------------------------------------- C
_C_CI = """\
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: pytest --cov=slugkit
      - run: python -m build
"""

FIXTURE_C: dict[str, Any] = {
    "name": "fixture-c-healthy",
    "commits": [
        {
            "message": "slugkit 1.2.0",
            "files": {
                "README.md": (
                    "# slugkit\n\nTiny library that turns arbitrary text into URL-safe slugs.\n\n"
                    "## Install\n\n```bash\npip install slugkit\n```\n\n"
                    "## Usage\n\n```python\nfrom slugkit import slugify\nslugify('Hello World!')  # 'hello-world'\n```\n\n"
                    "## Development\n\n```bash\npip install -e '.[dev]'\nruff check . && pytest\n```\n\n"
                    "See CONTRIBUTING.md for the review process.\n"
                ),
                "CONTRIBUTING.md": "# Contributing\n\nOpen a pull request; CI must pass and one maintainer review is required.\n",
                "LICENSE": "MIT License\n\nCopyright (c) 2024 slugkit authors\n",
                ".gitignore": "__pycache__/\n*.py[cod]\n.venv/\nbuild/\ndist/\n*.egg-info/\n.pytest_cache/\n.coverage\n.env\n",
                ".env.example": "# Only needed for the optional publish script\nPYPI_TOKEN=\n",
                "pyproject.toml": (
                    "[build-system]\nrequires = [\"hatchling>=1.18\"]\nbuild-backend = \"hatchling.build\"\n\n"
                    "[project]\nname = \"slugkit\"\nversion = \"1.2.0\"\nrequires-python = \">=3.10\"\n"
                    "dependencies = [\"unidecode>=1.3,<2\"]\n\n"
                    "[project.optional-dependencies]\ndev = [\"pytest>=8,<9\", \"pytest-cov>=5,<6\", \"ruff>=0.4,<1\", \"build>=1,<2\"]\n\n"
                    "[tool.ruff]\nline-length = 100\nsrc = [\"src\"]\n\n[tool.ruff.lint]\nselect = [\"E\", \"F\", \"I\", \"B\"]\n\n"
                    "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n"
                ),
                "src/slugkit/__init__.py": "from slugkit.core import slugify\n\n__all__ = [\"slugify\"]\n__version__ = \"1.2.0\"\n",
                "src/slugkit/core.py": (
                    "import re\n\nfrom unidecode import unidecode\n\n_NON_ALNUM = re.compile(r\"[^a-z0-9]+\")\n\n\n"
                    "def slugify(text: str, separator: str = \"-\") -> str:\n"
                    "    \"\"\"Convert text to a lowercase ASCII slug.\"\"\"\n"
                    "    ascii_text = unidecode(text).lower()\n"
                    "    return _NON_ALNUM.sub(separator, ascii_text).strip(separator)\n"
                ),
                "tests/test_core.py": (
                    "import pytest\n\nfrom slugkit import slugify\n\n"
                    "CASES =[(\"Hello World!\", \"hello-world\"), (\"Ünïcödé\", \"unicode\"), (\"\", \"\")]\n\n\n"
                    "@pytest.mark.parametrize(\"text,expected\", CASES)\n"
                    "def test_slugify(text, expected):\n    assert slugify(text) == expected\n\n\n"
                    "def test_separator():\n    assert slugify(\"a b\", separator=\"_\") == \"a_b\"\n"
                ),
                "tests/test_docs_examples.py": (
                    "# Example credentials from the AWS documentation; used to check that slugify\n"
                    "# does not choke on long uppercase tokens. They are not real keys.\n"
                    "EXAMPLE_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n\n\n"
                    "def test_long_token():\n    from slugkit import slugify\n\n    assert slugify(EXAMPLE_KEY) == EXAMPLE_KEY.lower()\n"
                ),
                ".github/workflows/ci.yml": _C_CI,
                ".github/dependabot.yml": (
                    "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule:\n      interval: weekly\n"
                    "  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n"
                ),
            },
        },
    ],
    "expected": [],
    "acceptable": [],
}

FIXTURES = [FIXTURE_A, FIXTURE_B, FIXTURE_C]
