"""Measure precision and recall of the agent on the synthetic fixtures.

    python eval/run_eval.py                 # build fixtures, run the agent, score
    python eval/run_eval.py --score-only    # re-score existing reports in eval/results/

A reported violation is a true positive when its rule_id is one of the answer
key's accepted IDs for an expected violation and its file matches (expected
file ``None`` matches any location). Each expected violation can be matched
once; further duplicates count as false positives, as in the assignment.
Findings listed as "acceptable" are defensible extras: neither rewarded nor
penalised.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.fixtures import FIXTURES  # noqa: E402

WORKDIR = ROOT / "eval" / "workdir"
RESULTS = ROOT / "eval" / "results"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Fixture Bot", "-c", "user.email=fixtures@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def build_fixture(fixture: dict[str, Any]) -> Path:
    repo = WORKDIR / fixture["name"]
    if repo.exists():
        shutil.rmtree(repo, onerror=lambda f, p, _: (Path(p).chmod(0o700), f(p)))
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    for commit in fixture["commits"]:
        for rel, content in commit["files"].items():
            path = repo / rel
            if content is None:
                _git(repo, "rm", "-q", rel)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8", newline="\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", commit["message"])
    return repo


def _file_matches(expected: str | None, reported: str | None) -> bool:
    if expected is None:
        return True
    if reported is None:
        return False
    return reported == expected or reported.startswith(expected.rstrip("/") + "/")


def score(fixture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    expected = fixture["expected"]
    matched: set[str] = set()
    tp, fp, neutral = [], [], []
    for v in report["violations"]:
        hit = next(
            (e for e in expected
             if e["id"] not in matched and v["rule_id"] in e["rule_ids"] and _file_matches(e["file"], v["file"])),
            None,
        )
        if hit:
            matched.add(hit["id"])
            tp.append((v["rule_id"], v["file"], hit["id"]))
            continue
        if any(v["rule_id"] in a["rule_ids"] and _file_matches(a["file"], v["file"]) for a in fixture["acceptable"]):
            neutral.append((v["rule_id"], v["file"]))
        else:
            fp.append((v["rule_id"], v["file"], v["description"]))
    scored = len(tp) + len(fp)
    return {
        "fixture": fixture["name"],
        "reported": len(report["violations"]),
        "true_positives": len(tp),
        "false_positives": fp,
        "acceptable_extras": len(neutral),
        "missed": [f"{e['id']}: {e['what']}" for e in expected if e["id"] not in matched],
        "precision": round(len(tp) / scored, 3) if scored else 1.0,
        "recall": round(len(tp) / len(expected), 3) if expected else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--score-only", action="store_true")
    parser.add_argument("--only", help="Run a single fixture by name")
    parser.add_argument("--max-steps", default="30")
    args = parser.parse_args()
    RESULTS.mkdir(parents=True, exist_ok=True)

    results = []
    for fixture in FIXTURES:
        if args.only and fixture["name"] != args.only:
            continue
        report_path = RESULTS / f"{fixture['name']}.json"
        if not args.score_only:
            repo = build_fixture(fixture)
            print(f"\n=== {fixture['name']} ===", flush=True)
            code = subprocess.call([
                sys.executable, str(ROOT / "agent.py"),
                "--repo", f"https://github.com/eval/{fixture['name']}",
                "--local-path", str(repo),
                "--output", str(report_path),
                "--max-steps", args.max_steps,
            ])
            if code != 0:
                print(f"agent failed on {fixture['name']} (exit {code})")
                continue
        if not report_path.exists():
            continue
        results.append(score(fixture, json.loads(report_path.read_text(encoding="utf-8"))))

    tp = sum(r["true_positives"] for r in results)
    fp = sum(len(r["false_positives"]) for r in results)
    expected = sum(len(f["expected"]) for f in FIXTURES if any(r["fixture"] == f["name"] for r in results))
    summary = {
        "fixtures": results,
        "overall": {
            "true_positives": tp,
            "false_positives": fp,
            "expected": expected,
            "precision": round(tp / (tp + fp), 3) if tp + fp else 1.0,
            "recall": round(tp / expected, 3) if expected else None,
        },
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
