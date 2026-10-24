from tests.conftest import add_commit
from tools import TOOL_SCHEMAS, RepoTools

AWS = "AKIA" + "Q3EGRTZXMPLW7Y2B"

WORKFLOW = """\
name: CI
on:
  push:
    branches: [master]
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someone/action@master
      - run: pip install -r requirements.txt
      - run: pytest || true
        continue-on-error: true
"""


def tools_for(repo, branch="main"):
    return RepoTools(repo, default_branch=branch)


def test_list_files_shows_tracked_files_and_records_them(repo_factory):
    repo = repo_factory({"README.md": "# demo\n", "src/app.py": "print('hi')\n"})
    t = tools_for(repo)
    out = t.list_files()
    assert "README.md" in out and "src/app.py" in out
    assert {"README.md", "src/app.py"} <= t.listed_files
    assert "src/app.py" in t.list_files(path="src")


def test_read_file_numbers_lines_masks_secrets_and_tracks_evidence(repo_factory):
    repo = repo_factory({"config.py": f"DEBUG = True\nAWS_KEY = '{AWS}'\n"})
    t = tools_for(repo)
    out = t.read_file("config.py")
    assert "1 | DEBUG = True" in out
    assert AWS not in out and "[REDACTED:aws_access_key_id]" in out
    assert t.content_seen["config.py"] is None  # whole file seen


def test_read_file_range_and_errors(repo_factory):
    repo = repo_factory({"a.txt": "\n".join(f"line{i}" for i in range(1, 11)) + "\n", "bin.dat": b"\x00\x01\x02"})
    t = tools_for(repo)
    out = t.read_file("a.txt", start_line=3, end_line=4)
    assert "3 | line3" in out and "line5" not in out
    assert t.content_seen["a.txt"] == {3, 4}
    assert "binary" in t.execute("read_file", {"path": "bin.dat"}).output
    assert "not found" in t.execute("read_file", {"path": "missing.py"}).output


def test_read_file_refuses_path_traversal(repo_factory):
    repo = repo_factory({"a.txt": "x\n"})
    result = tools_for(repo).execute("read_file", {"path": "../../etc/passwd"})
    assert not result.ok and "outside the repository" in result.output


def test_search_code_finds_matches_with_locations(repo_factory):
    repo = repo_factory({"a.py": "import os\npath = 'C:\\\\Users\\\\bob\\\\data'\n", "b.md": "nothing\n"})
    t = tools_for(repo)
    out = t.search_code(r"C:\\\\Users", file_glob="*.py")
    assert "a.py:2:" in out
    assert t.content_seen["a.py"] == {2}
    assert "No matches" in t.search_code("zzz_not_there")
    assert not t.execute("search_code", {"pattern": "("}).ok


def test_git_log_shows_history_including_deleted_files(repo_factory):
    repo = repo_factory({"README.md": "# x\n", ".env": "TOKEN=abc\n"})
    add_commit(repo, {".env": None}, "remove env file")
    out = tools_for(repo).git_log()
    assert "remove env file" in out and "D\t.env" in out
    assert "Total commits on main: 2" in out


def test_scan_secrets_current_files_history_and_sensitive_files(repo_factory):
    repo = repo_factory({"app.py": f"KEY = '{AWS}'\n", ".env": "X=1\n", ".env.example": "API_KEY=\n"})
    add_commit(repo, {"old.py": "password = 'Zx9!kLm2Qp'\n"}, "add old")
    add_commit(repo, {"old.py": None}, "drop old")
    out = tools_for(repo).scan_secrets()
    assert "Sensitive files tracked in git: .env" in out and ".env.example" not in out.split("\n")[0]
    assert "app.py:1 [aws_access_key_id]" in out
    assert "old.py" in out and "no longer tracked" in out
    assert AWS not in out and "Zx9!kLm2Qp" not in out


def test_inspect_workflows_flags_risky_patterns(repo_factory):
    repo = repo_factory({".github/workflows/ci.yml": WORKFLOW, "requirements.txt": "flask\n"})
    out = tools_for(repo).inspect_workflows()
    assert "pull_request_target" in out
    assert "write-all" in out
    assert "continue-on-error" in out
    assert "|| true" in out
    assert "@master" in out
    assert "do not include the default branch 'main'" in out
    assert "checks out pull-request head code" in out


def test_inspect_workflows_handles_missing_and_invalid(repo_factory):
    repo = repo_factory({"README.md": "x\n"})
    assert "No GitHub Actions workflows" in tools_for(repo).inspect_workflows()
    repo2 = repo_factory({".github/workflows/bad.yml": "on: [push\njobs: {"})
    assert "INVALID YAML" in tools_for(repo2).inspect_workflows()


def test_inspect_dependencies_classifies_and_detects_conflicts(repo_factory):
    repo = repo_factory({
        "requirements.txt": "flask\nrequests==2.31.0\nnumpy>=1.20\n--index-url http://pypi.internal/simple\n",
        "pyproject.toml": '[project]\nname="x"\nversion="1"\ndependencies=["requests==2.32.0"]\n[tool.ruff]\n',
    })
    out = tools_for(repo).inspect_dependencies()
    assert "flask  -> UNPINNED" in out
    assert "requests ==2.31.0 -> pinned" in out
    assert "numpy >=1.20 -> lower-bound only" in out
    assert "insecure http" in out
    assert "Inconsistent specifications" in out and "requests" in out
    assert "Lockfiles: none found" in out
    assert "ruff" in out


def test_run_ruff_reports_real_errors(repo_factory):
    repo = repo_factory({"bad.py": "import os\nprint(undefined_name)\n"})
    out = tools_for(repo).run_ruff()
    assert "F821" in out or "F401" in out


def test_git_status_reports_clean_tree(repo_factory):
    repo = repo_factory({"README.md": "x\n"})
    assert "working tree clean" in tools_for(repo).git_status()


def test_tools_do_not_modify_the_repository(repo_factory):
    repo = repo_factory({"a.py": "import os\n", ".github/workflows/ci.yml": WORKFLOW, "requirements.txt": "x\n"})
    t = tools_for(repo)
    for name, args in [("list_files", {}), ("read_file", {"path": "a.py"}), ("search_code", {"pattern": "os"}),
                       ("git_log", {}), ("inspect_workflows", {}), ("inspect_dependencies", {}),
                       ("scan_secrets", {}), ("run_ruff", {})]:
        assert t.execute(name, args).ok, name
    assert "working tree clean" in t.git_status()


def test_execute_handles_unknown_tools_and_bad_arguments(repo_factory):
    t = tools_for(repo_factory({"a.py": "x = 1\n"}))
    assert "unknown tool" in t.execute("rm_rf", {}).output
    assert "invalid arguments" in t.execute("read_file", {"nope": 1}).output


def test_schemas_cover_all_handlers():
    names = {s["function"]["name"] for s in TOOL_SCHEMAS}
    assert {"list_files", "read_file", "search_code", "git_log"} <= names
    assert names == set(RepoTools(".")._handlers)  # every schema has a handler and vice versa


def test_history_scan_skips_secrets_still_present(repo_factory):
    repo = repo_factory({"app.py": f"KEY = '{AWS}'\n"})
    out = tools_for(repo).scan_secrets()
    history = out.split("Possible secrets in git history")[1]
    assert history.splitlines()[0].endswith(": 0")
