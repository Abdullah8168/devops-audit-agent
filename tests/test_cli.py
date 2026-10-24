import json

import pytest

import agent as cli
from auditor.repo import InvalidRepoURL, normalize_github_url
from tests.conftest import FakeLLM, violation


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/psf/requests", "https://github.com/psf/requests"),
    ("https://github.com/psf/requests.git", "https://github.com/psf/requests"),
    ("https://github.com/psf/requests/", "https://github.com/psf/requests"),
    ("http://www.github.com/a-b/c.d_e", "https://github.com/a-b/c.d_e"),
])
def test_valid_urls_are_normalized(url, expected):
    assert normalize_github_url(url) == expected


@pytest.mark.parametrize("url", ["", "github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a",
                                 "https://github.com/a/b/tree/main", "file:///etc", "https://github.com/a/b;rm -rf"])
def test_invalid_urls_are_rejected(url):
    with pytest.raises(InvalidRepoURL):
        normalize_github_url(url)


def test_cli_rejects_invalid_url_with_nonzero_exit(tmp_path, capsys):
    code = cli.main(["--repo", "not-a-url", "--output", str(tmp_path / "r.json")])
    assert code == cli.EXIT_USAGE
    assert "Not a valid GitHub repository URL" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_cli_missing_api_key_fails_cleanly(tmp_path, monkeypatch, capsys):
    for var in ("LLM_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.setenv(var, "")
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    code = cli.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")])
    assert code == cli.EXIT_LLM
    assert "No API key configured" in capsys.readouterr().err


def test_cli_end_to_end_with_fake_llm(repo_factory, tmp_path, monkeypatch):
    repo = repo_factory({"config.py": "a = 1\nAPI_KEY = 'Zq8LmN3pWx7Kd2'\n"})
    fake = FakeLLM([
        [("read_file", {"path": "config.py"})],
        [("submit_report", {"violations": [violation()]})],
    ])
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setattr("auditor.llm.OpenAICompatibleClient", lambda settings: fake)
    out = tmp_path / "report.json"
    code = cli.main(["--repo", "https://github.com/o/r", "--output", str(out), "--local-path", str(repo), "--quiet"])
    assert code == cli.EXIT_OK
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["repository"] == "https://github.com/o/r"
    assert data["violations"][0]["rule_id"] == "SEC-001"
    assert "Zq8LmN3pWx7Kd2" not in out.read_text(encoding="utf-8")
    assert (tmp_path / "report.json.trace.jsonl").exists()
    assert "Zq8LmN3pWx7Kd2" not in (tmp_path / "report.json.trace.jsonl").read_text(encoding="utf-8")


def test_cli_reports_clone_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setattr("auditor.llm.OpenAICompatibleClient", lambda settings: FakeLLM([]))
    code = cli.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json"),
                     "--local-path", str(tmp_path / "does-not-exist")])
    assert code == cli.EXIT_REPO
    assert "not a git repository" in capsys.readouterr().err
