# DevOps Audit Agent

An LLM-driven agent that audits a public GitHub repository for DevOps best-practice violations and writes an evidence-backed JSON report.

The agent is **not** a scanner with an LLM summary on top. The language model drives the investigation: it looks at the repository, forms hypotheses ("the CI workflow triggers on `master` but the default branch is `main`"), chooses which read-only tool to call next, interprets the result and follows up, until it can back each finding with evidence. Agent loop, tool dispatch and control flow are plain Python, with no agent frameworks (LangChain, LangGraph, n8n, ...).

```
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

---

## Contents

1. [Quick start](#quick-start)
2. [Configuration](#configuration)
3. [Usage](#usage)
4. [Output format](#output-format)
5. [Architecture](#architecture)
6. [Inspection tools](#inspection-tools)
7. [How false positives are kept down](#how-false-positives-are-kept-down)
8. [Safety](#safety)
9. [Evaluation](#evaluation)
10. [Tests](#tests)
11. [Project structure](#project-structure)
12. [Limitations](#limitations)

---

## Quick start

Requirements: **Python 3.10+** and **Git** on `PATH`.

```bash
git clone https://github.com/Abdullah8168/devops-audit-agent.git
cd devops-audit-agent

python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env          # Windows: copy .env.example .env
# edit .env and set LLM_API_KEY (see Configuration)

python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

## Configuration

Settings are read from environment variables, or from a `.env` file in the project directory (`.env` is git-ignored; `.env.example` lists every variable).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `LLM_API_KEY` | yes | – | API key of the LLM provider |
| `LLM_BASE_URL` | no | Gemini's OpenAI-compatible endpoint | Any OpenAI-compatible chat-completions endpoint |
| `LLM_MODEL` | no | `gemini-3.5-flash` | Model name; must support tool/function calling |
| `LLM_MIN_INTERVAL` | no | `0` | Minimum seconds between LLM requests (helps with free-tier rate limits) |
| `LLM_FALLBACK_MODELS` | no | – | Comma-separated models to switch to mid-run if the main model's quota is exhausted, it is not found, or it stays overloaded |

The client speaks the OpenAI-compatible chat-completions API, so you can switch providers without changing code:

| Provider | `LLM_BASE_URL` | Example `LLM_MODEL` |
|---|---|---|
| Google Gemini (default, free tier) | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-3.5-flash` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |

`GEMINI_API_KEY`, `GOOGLE_API_KEY` and `OPENAI_API_KEY` are also accepted when `LLM_API_KEY` is not set.

## Usage

```
python agent.py --repo URL [--output report.json] [--max-steps 30] [--model NAME]
                [--trace PATH|none] [--quiet] [--local-path DIR]
```

| Option | Meaning |
|---|---|
| `--repo` | Public GitHub repository URL (`https://github.com/owner/name`, optional `.git` / trailing slash) |
| `--output` | Report path (default `report.json`) |
| `--max-steps` | Maximum LLM turns (default 30). The agent is warned before the budget runs out and is then required to submit |
| `--model` | Override `LLM_MODEL` |
| `--trace` | JSONL tool-call trace (default `<output>.trace.jsonl`; `none` disables it) |
| `--quiet` | Hide per-step progress output |
| `--local-path` | Audit an existing local checkout instead of cloning; used for tests and offline evaluation |

Progress goes to stderr. Each step shows the model's stated intent and the tool it called:

```
[step 3] thinking: The CI workflow triggers on master; the default branch is main. Reading the workflow to confirm.
[step 3] read_file(path='.github/workflows/ci.yml') -> .github/workflows/ci.yml (lines 1-24 of 24)
```

The run is fully unattended: no prompts, no interaction.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Inspection completed and report written (possibly with zero violations) |
| 2 | Invalid input (e.g. not a GitHub repository URL) |
| 3 | Repository could not be cloned (missing, private, network) |
| 4 | LLM provider error (no/invalid key, quota exhausted, model not found) |
| 5 | Agent could not finish, or the report could not be written |
| 1 | Unexpected internal error |
| 130 | Interrupted |

## Output format

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "config.py:17 assigns a literal to API_KEY ([REDACTED:len=32])",
      "recommendation": "Load the key from an environment variable or a secrets manager and rotate it"
    }
  ]
}
```

- Every violation has all eight fields. `severity` is one of `critical`, `high`, `medium`, `low`.
- `file` / `line` are JSON `null` when not applicable (e.g. a missing README).
- Secret values never appear: they are masked as `[REDACTED:<kind>]` before they reach the LLM, the trace or the report.
- A clean repository produces `"violations": []`.
- Rule IDs come from a fixed catalog ([auditor/rules.py](auditor/rules.py)) so results are comparable across runs: `HYG` repository hygiene, `DEP` dependencies, `CQ` code quality, `TST` testing, `CI` GitHub Actions/CI, `SEC` security, `CFG` configuration, `COL` collaboration, `BLD` build & release. Each category has a `-099` ID for genuine issues outside the predefined rules.

[sample_report.json](sample_report.json) is real output from the agent (see [Evaluation](#evaluation)).

## Architecture

```mermaid
flowchart TD
    CLI["agent.py<br/>CLI, validation, exit codes"] --> CLONE["auditor/repo.py<br/>safe clone into temp dir"]
    CLONE --> LOOP
    subgraph LOOP["auditor/agent_loop.py — Observe → Reason → Act"]
        direction TB
        LLM["LLM (auditor/llm.py)<br/>states intent, picks tool calls"] -->|tool calls| DISPATCH["dispatch + cache + budget"]
        DISPATCH --> TOOLS["tools.py<br/>9 read-only tools"]
        TOOLS -->|redacted, truncated output| LLM
        LLM -->|submit_report| GROUND["auditor/report.py<br/>validate + ground + dedupe"]
        GROUND -->|unsupported findings → verify once| LLM
    end
    GROUND --> OUT["report.json"]
    LOOP -.-> TRACE["trace.jsonl<br/>every step and tool call"]
```

### The agent loop ([auditor/agent_loop.py](auditor/agent_loop.py))

1. **Observe.** The LLM receives the repository URL, default branch and commit count. Everything else it learns by calling tools.
2. **Reason.** Each turn the model writes a sentence or two on what it is checking and why. This text is recorded in the trace.
3. **Select tool.** The model emits one or more function calls (OpenAI tool-calling format). Several independent calls can be made in one turn.
4. **Execute.** The loop validates arguments and dispatches to [tools.py](tools.py). Unknown tools, malformed JSON and tool failures return as error text to the model instead of crashing the run. Identical repeated calls are served from cache.
5. **Interpret.** Tool output (secrets masked, size-capped) is appended to the conversation and the model decides the next step, including follow-ups such as reading the exact lines a search hit pointed to.
6. **Report.** The model calls `submit_report`. Findings are validated and **grounded** (see below). If some cite evidence the agent never looked at, the model gets one chance to verify or drop them. The final report is then written atomically.

Budget control: the model is told how many turns it has, warned when four remain, and on the last turn only `submit_report` is offered. When the conversation grows large, the oldest tool outputs are elided (the model can re-run a tool if it needs them).

### LLM client ([auditor/llm.py](auditor/llm.py))

A thin wrapper over the plain `openai` SDK pointed at any OpenAI-compatible endpoint. It adds bounded retries with exponential backoff (honouring `retry-after`), optional request throttling for free tiers, automatic switching to `LLM_FALLBACK_MODELS` when a model's quota runs out or it is unavailable, fail-fast errors for invalid keys, and removal of any API key the provider echoes back in error messages.

## Inspection tools

All tools are read-only and defined in [tools.py](tools.py). Their JSON schemas are sent to the model, which decides when to use them.

| Tool | What it does |
|---|---|
| `list_files(path, max_depth)` | Git-tracked files with sizes, so committed junk is visible |
| `read_file(path, start_line, end_line)` | Line-numbered content (max 400 lines per call), path-traversal protected, binary-aware |
| `search_code(pattern, file_glob, ignore_case)` | Regex search returning `file:line: text` |
| `git_log(max_count, path, show_files)` | Commit history with added/deleted files |
| `inspect_workflows()` | Parses GitHub Actions YAML: triggers, permissions, jobs, steps, plus line-numbered heuristic observations (`pull_request_target`, PR-head checkout, `continue-on-error`, `\|\| true`, `write-all`, script injection, mutable action refs, branch filters that exclude the default branch, workflows without a test command). Also lists other CI systems, dependabot and CODEOWNERS |
| `inspect_dependencies()` | Finds manifests and lockfiles across ecosystems, classifies each Python requirement (pinned / range / unpinned / VCS), flags insecure indexes and **cross-manifest inconsistencies** |
| `scan_secrets(include_history)` | Provider-specific token patterns plus entropy-checked generic assignments in current files, sensitive tracked files (`.env`, keys), and secrets that exist **only in git history**. Values are always masked; documented dummy keys are labelled as such |
| `run_ruff(path)` | Ruff static analysis. Never imports or executes repository code; runs with `--no-cache` so nothing is written |
| `git_status()` | Proves the working tree is unchanged |

The specialised tools return *observations*, not verdicts. The prompt requires the model to confirm them (usually by reading the file) before reporting.

## How false positives are kept down

The hidden-repository evaluation penalises false positives as much as misses, so several layers work against them:

1. **Prompted precision rules** ([auditor/prompts.py](auditor/prompts.py)): equivalent alternatives are not defects (pyproject vs requirements.txt, ruff vs flake8, tox vs CI-run pytest, other CI systems), no claims about branch protection, libraries need no lockfile, placeholders and documented example keys are not leaks, and small projects don't need CODEOWNERS or release pipelines. Each root cause is reported once.
2. **Evidence grounding** ([auditor/report.py](auditor/report.py)): a finding that names a file must refer to an existing file the agent observed through a tool. A finding with a line number must point to a line the agent actually saw, within the file's length. Ungrounded findings go back to the model once for verification; if they still lack evidence, they are discarded and logged in the trace.
3. **Normalisation and de-duplication**: severities and categories are validated, catalog rule IDs fix the category, and duplicates (same rule and location) are merged, keeping the higher severity.
4. **Tool-level care**: history secret scanning skips secrets still in the current tree (already reported there), and documented dummy credentials such as `AKIAIOSFODNN7EXAMPLE` are labelled rather than flagged.

## Safety

- **The target repository is never modified.** It is cloned into a fresh temporary directory and deleted afterwards. All tools are read-only, and a fingerprint of `HEAD` plus `git status` is compared before and after the audit.
- **No repository code is executed.** Git hooks are not cloned, submodules are not initialised, LFS smudging is disabled and `core.symlinks=false` is set. `run_ruff` is static analysis only. The test suite of the audited repository is deliberately *not* run: doing so safely requires container isolation (see [Limitations](#limitations)).
- **No interactive prompts.** `GIT_TERMINAL_PROMPT=0`, so a private or non-existent repository fails immediately with exit code 3 instead of hanging.
- **Secrets never leak.** Every tool output, trace record, error message and report field passes through redaction ([auditor/redaction.py](auditor/redaction.py)). The model only ever sees `[REDACTED:<kind>]`.
- **Bounded resources.** Every git and tool call has a timeout, file reads and outputs are size-capped, and LLM calls have a retry limit and turn budget.
- **Input validation.** Only `https://github.com/<owner>/<repo>` URLs are accepted, and paths given to tools are confined to the repository root.

## Evaluation

[eval/](eval/) contains three synthetic repositories with answer keys, mirroring the three hidden-repository types in the assignment:

| Fixture | Type | Injected defects |
|---|---|---|
| `fixture-a-obvious` | (A) obvious issues | 8: no README, no .gitignore, tracked bytecode, committed `.env`, hardcoded credentials, unpinned deps, no tests, no CI |
| `fixture-b-subtle` | (B) subtle CI/security/config | 9: trigger on wrong branch, `pytest \|\| true`, `pull_request_target` running PR code with secrets, `write-all`, script injection via PR title, machine-specific path, committed IDE settings, token only in git history, conflicting dependency versions |
| `fixture-c-healthy` | (C) healthy, false-positive trap | 0: includes traps such as AWS's documented example key in a test, `.env.example`, a library without a lockfile |

```bash
python eval/run_eval.py               # builds the fixtures, runs the agent on each, scores it
python eval/run_eval.py --score-only  # re-scores existing reports
```

A finding counts as correct if its rule ID is one the answer key accepts for that defect and its file matches. Duplicates count as false positives. Defensible extras listed in the key as "acceptable" are neither rewarded nor penalised.

<!-- EVAL-RESULTS -->
### Results

Latest run (Gemini free tier, `--max-steps 30`). The reports and full tool-call traces are in [eval/sample_results/](eval/sample_results/):

| Fixture | Reported | Correct | False positives | Missed | Precision | Recall | Steps / tool calls |
|---|---|---|---|---|---|---|---|
| A: obvious | 10 | 8 | 0 | 0 | 1.00 | 1.00 | 7 / 11 |
| B: subtle | 9 | 9 | 0 | 0 | 1.00 | 1.00 | 16 / 22 |
| C: healthy | 0 | – | 0 | – | 1.00 | – | 14 / 13 |
| **Total** | **19** | **17** | **0** | **0** | **1.00** | **1.00** | |

A's two extra findings (Flask `debug=True` and a never-closed DB connection in `app.py`) are true but outside the answer key, so they are scored as acceptable extras. The primary model's free daily quota ran out during this run; the agent switched automatically through `LLM_FALLBACK_MODELS` (`gemini-3-flash-preview`, then `gemini-3.5-flash-lite`) and finished every fixture.

How the evaluation shaped the agent (kept here for transparency):

- **First run (`gemini-3.5-flash`): B recall 8/9.** The agent found the token committed in git history, but the report's grounding check discarded the finding because the file no longer exists. That is exactly the situation the finding describes. Grounding now accepts files the agent observed in git history (with `line: null`). A regression test covers this.
- **Answer-key corrections, not agent changes:** one root cause can be visible in several files (tracked bytecode *and* `server.log` are both HYG-004), so the key accepts either location. The DB-connection leak and a hardcoded DB host IP (CFG-001 vs CFG-003) were real defects in the fixture code that the key had not listed, so they are now "acceptable".
- These are small, self-written fixtures and single runs, and LLM output varies between runs and models. Treat the numbers as a sanity check of the pipeline, not as a benchmark.
<!-- /EVAL-RESULTS -->

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite runs offline: the LLM is replaced by a scripted fake. It covers:

- **Tools**: each tool on throwaway git repos built per test, path-traversal refusal, binary files, invalid regexes, invalid YAML, history-only secrets, and a check that no tool modifies the repository.
- **Agent behaviour**: LLM-chosen follow-up calls, parallel calls, the evidence-verification round, discarding unsupported findings, malformed/unknown tool calls, budget enforcement, nudging and rescue when the model stops calling tools, tool-call caching, and the trace.
- **Report contract**: schema validation, normalisation, grounding, de-duplication, secret scrubbing, atomic writes, empty reports.
- **CLI**: URL validation, exit codes, missing API key, clone failure, and an end-to-end run that verifies no secret reaches the report or trace.
- **Fixtures**: the evaluation repositories build correctly and the tools surface the evidence for every injected defect.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs ruff and the tests on Linux and Windows with Python 3.10 and 3.12, using read-only token permissions.

## Project structure

```
agent.py                 CLI entry point (arguments, exit codes, orchestration)
tools.py                 inspection tools + JSON schemas + dispatcher
auditor/
  agent_loop.py          Observe -> Reason -> Act loop, budget, grounding round, context compaction
  llm.py                 OpenAI-compatible client: retries, throttling, safe errors
  prompts.py             system prompt (strategy, precision rules, severity guide) and loop messages
  rules.py               rule-ID catalog
  report.py              validation, evidence grounding, de-duplication, JSON writing
  repo.py                URL validation, safe clone, unchanged-workspace check
  redaction.py           secret detection and masking
  trace.py               JSONL trace of every step
eval/
  fixtures.py            three synthetic repositories with answer keys
  run_eval.py            builds fixtures, runs the agent, computes precision/recall
tests/                   pytest suite (offline)
sample_report.json       real agent output
eval/sample_results/     reports + tool-call traces from the evaluation run
.env.example             configuration template (no credentials)
```

## Limitations

- **Tests of the audited repository are not executed.** Running untrusted code safely needs container isolation (e.g. a network-less Docker sandbox). Instead the agent checks statically whether tests exist, look meaningful and are run by CI.
- **Remote settings are invisible.** Branch protection, required reviews, secret scanning and environment protection rules live in GitHub settings, not in files, so the agent makes no claims about them.
- **LLM variance.** Results can differ slightly between runs and models. The low temperature, catalog rule IDs, grounding and de-duplication reduce this but cannot remove it.
- **Budget.** Very large repositories may not be fully explored within the turn budget; raise `--max-steps` if needed.
- **Git history.** Only the default branch is cloned, and secret history scanning covers its most recent 300 commits.
