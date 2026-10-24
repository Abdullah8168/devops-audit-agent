"""DevOps repository auditing agent - command-line entry point.

Usage:
    python agent.py --repo https://github.com/<owner>/<repo> --output report.json

Exit codes:
    0  inspection completed and report written (possibly with zero violations)
    1  unexpected internal error
    2  invalid command-line input (e.g. not a GitHub URL)
    3  repository could not be cloned or read
    4  LLM provider error (missing/invalid key, quota, unreachable)
    5  the agent could not finish the audit or the report could not be written
  130  interrupted by the user
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_REPO, EXIT_LLM, EXIT_AGENT, EXIT_INTERRUPT = 0, 1, 2, 3, 4, 5, 130


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="AI agent that audits a public GitHub repository for DevOps best-practice violations.",
    )
    parser.add_argument("--repo", required=True, help="Public GitHub repository URL, e.g. https://github.com/owner/name")
    parser.add_argument("--output", default="report.json", help="Path of the JSON report to write (default: report.json)")
    parser.add_argument("--max-steps", type=int, default=30, help="Maximum LLM turns (default: 30)")
    parser.add_argument("--model", default=None, help="Override LLM_MODEL from the environment")
    parser.add_argument("--trace", default=None,
                        help="Path of the JSONL tool-call trace (default: <output>.trace.jsonl; 'none' to disable)")
    parser.add_argument("--local-path", default=None,
                        help="Audit an existing local git checkout instead of cloning (testing/offline evaluation)")
    parser.add_argument("--quiet", action="store_true", help="Only print errors and the final summary")
    args = parser.parse_args(argv)
    if args.max_steps < 3 or args.max_steps > 200:
        parser.error("--max-steps must be between 3 and 200")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Imports are deferred so that `--help` works even before dependencies are installed.
    try:
        from dotenv import load_dotenv

        from auditor.agent_loop import AgentConfig, AgentError, AuditAgent
        from auditor.llm import LLMError, LLMSettings, OpenAICompatibleClient
        from auditor.repo import (
            InvalidRepoURL,
            RepoError,
            clone_repository,
            normalize_github_url,
            open_local_repository,
        )
        from auditor.report import ReportError, build_report, write_report
        from auditor.trace import TraceLogger
        from tools import RepoTools
    except ImportError as exc:
        print(f"error: missing dependency ({exc}). Run: pip install -r requirements.txt", file=sys.stderr)
        return EXIT_INTERNAL

    load_dotenv(Path(__file__).resolve().parent / ".env")
    load_dotenv()  # also honour a .env in the current directory

    try:
        repo_url = normalize_github_url(args.repo)
    except InvalidRepoURL as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    trace_path = None if (args.trace or "").lower() == "none" else (args.trace or f"{args.output}.trace.jsonl")
    trace = TraceLogger(trace_path, console=None if args.quiet else sys.stderr)
    workspace = None
    try:
        llm = OpenAICompatibleClient(LLMSettings.from_env(model=args.model))

        trace.say(f"Cloning {repo_url} ...")
        workspace = open_local_repository(args.local_path, url=repo_url) if args.local_path else clone_repository(repo_url)
        trace.say(f"Workspace ready: branch={workspace.default_branch} head={workspace.head_commit} "
                  f"commits={workspace.commit_count}; model={llm.model}")

        tools = RepoTools(workspace.path, default_branch=workspace.default_branch)
        agent = AuditAgent(
            llm, tools, repo_url, AgentConfig(max_steps=args.max_steps), trace,
            head_commit=workspace.head_commit, commit_count=workspace.commit_count,
        )
        result = agent.run()

        unchanged = workspace.verify_unchanged()
        trace.event("workspace_check", unchanged=unchanged)
        if not unchanged:
            trace.say("warning: the workspace changed during the audit (this should never happen)")

        path = write_report(build_report(repo_url, result.violations), args.output)
        counts = Counter(v["severity"] for v in result.violations)
        breakdown = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s])
        print(
            f"Audit complete: {len(result.violations)} violation(s)"
            + (f" ({breakdown})" if breakdown else "")
            + f" in {result.steps} steps / {result.tool_calls} tool calls, {result.duration_s}s. "
            + f"Report: {path}" + (f" | Trace: {trace_path}" if trace_path else ""),
            file=sys.stderr,
        )
        if result.rejected:
            trace.say(f"{len(result.rejected)} unsupported finding(s) were discarded (see trace).")
        return EXIT_OK
    except RepoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REPO
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_LLM
    except (AgentError, ReportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AGENT
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return EXIT_INTERRUPT
    except Exception as exc:  # noqa: BLE001 - last-resort handler, keeps the exit code meaningful
        print(f"error: unexpected failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    finally:
        trace.close()
        if workspace is not None:
            workspace.cleanup()


if __name__ == "__main__":
    sys.exit(main())
