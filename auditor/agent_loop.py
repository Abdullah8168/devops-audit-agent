"""The agent loop: Observe -> Reason -> Select tool -> Execute -> Interpret -> Report.

Control flow is plain Python (no agent framework). Each turn the LLM sees the
conversation so far, explains what it wants to check, and requests tool calls.
The loop executes them, feeds the results back, and repeats until the LLM calls
``submit_report`` or the step budget runs out.

Safeguards:
- step budget with an early warning and a forced final ``submit_report`` turn
- malformed / unknown tool calls are answered with an error instead of crashing
- identical repeated tool calls are served from cache
- old tool outputs are elided when the conversation grows too large
- submitted findings are grounded against what the tools actually observed; the
  agent gets one chance to verify or drop unsupported findings
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from auditor.llm import ChatModel, LLMResponse, ToolCall
from auditor.prompts import (
    BUDGET_WARNING,
    FINAL_TURN,
    GROUNDING_FEEDBACK,
    NO_TOOL_NUDGE,
    SUBMIT_REPORT_SCHEMA,
    initial_user_message,
    system_prompt,
)
from auditor.report import Rejection, process_violations
from auditor.trace import TraceLogger
from tools import TOOL_SCHEMAS, RepoTools


class AgentError(Exception):
    """The agent could not complete the audit."""


@dataclass
class AgentConfig:
    max_steps: int = 30
    warn_remaining: int = 4
    max_calls_per_turn: int = 10
    context_char_budget: int = 150_000
    keep_recent_tool_outputs: int = 8
    max_nudges: int = 2


@dataclass
class AgentResult:
    violations: list[dict[str, Any]]
    rejected: list[Rejection]
    summary: str
    steps: int
    tool_calls: int
    duration_s: float
    tools_used: dict[str, int] = field(default_factory=dict)


class AuditAgent:
    def __init__(
        self,
        llm: ChatModel,
        tools: RepoTools,
        repo_url: str,
        config: AgentConfig | None = None,
        trace: TraceLogger | None = None,
        head_commit: str = "unknown",
        commit_count: int = 0,
    ):
        self.llm = llm
        self.tools = tools
        self.repo_url = repo_url
        self.config = config or AgentConfig()
        self.trace = trace or TraceLogger(console=None)
        self.head_commit = head_commit
        self.commit_count = commit_count
        self.schemas = [*TOOL_SCHEMAS, SUBMIT_REPORT_SCHEMA]
        self.messages: list[dict[str, Any]] = []
        self._cache: dict[str, str] = {}
        self._tool_names: dict[str, str] = {}  # tool_call_id -> tool name (for context compaction)
        self.tool_call_count = 0
        self.tools_used: dict[str, int] = {}

    # ------------------------------------------------------------------ public
    def run(self) -> AgentResult:
        cfg = self.config
        start = time.monotonic()
        self.messages = [
            {"role": "system", "content": system_prompt()},
            {
                "role": "user",
                "content": initial_user_message(
                    self.repo_url, self.tools.default_branch, self.head_commit, self.commit_count, cfg.max_steps
                ),
            },
        ]
        self.trace.event("run_start", repository=self.repo_url, model=getattr(self.llm, "model", "?"),
                         max_steps=cfg.max_steps)

        submitted: list[Any] | None = None
        summary = ""
        grounding_feedback_given = False
        nudges = 0
        step = 0

        while step < cfg.max_steps:
            step += 1
            remaining = cfg.max_steps - step
            final_turn = remaining == 0
            if final_turn:
                self.messages.append({"role": "user", "content": FINAL_TURN})
            elif remaining == cfg.warn_remaining:
                self.messages.append({"role": "user", "content": BUDGET_WARNING.format(remaining=remaining)})

            # On the final turn only submit_report is offered, which forces a conclusion
            # without relying on provider support for tool_choice="required".
            tools = [SUBMIT_REPORT_SCHEMA] if final_turn else self.schemas
            response = self.llm.chat(self.messages, tools)
            self._log_response(step, response)
            self.messages.append(response.message)

            if not response.tool_calls:
                nudges += 1
                if nudges > cfg.max_nudges:
                    self.trace.say(f"[step {step}] model stopped calling tools")
                    break
                self.messages.append({"role": "user", "content": NO_TOOL_NUDGE})
                continue

            report_call: tuple[ToolCall, dict[str, Any]] | None = None
            for i, call in enumerate(response.tool_calls):
                if call.name == "submit_report":
                    report_call = (call, call.arguments)
                    continue  # answered below, after the other calls in this turn
                if i >= cfg.max_calls_per_turn:
                    self._reply(call, f"Skipped: at most {cfg.max_calls_per_turn} tool calls per turn.")
                    continue
                self._run_tool(step, call)

            if report_call:
                call, args = report_call
                if call.parse_error:
                    self._reply(call, f"ERROR: {call.parse_error}. Call submit_report again with valid JSON.")
                    continue
                violations = args.get("violations")
                if not isinstance(violations, list):
                    self._reply(call, "ERROR: 'violations' must be an array. Call submit_report again.")
                    continue
                summary = str(args.get("summary") or "")
                accepted, rejected = process_violations(violations, self.tools)
                self.trace.event("report_submitted", step=step, proposed=len(violations), accepted=len(accepted),
                                 rejected=[r.describe() for r in rejected])
                grounding_problems = [r for r in rejected if "inspect" in r.reason or "read" in r.reason]
                if grounding_problems and not grounding_feedback_given and remaining >= 2:
                    grounding_feedback_given = True
                    problems = "\n".join(r.describe() for r in grounding_problems)
                    self._reply(call, GROUNDING_FEEDBACK.format(problems=problems))
                    self.trace.say(f"[step {step}] {len(grounding_problems)} unsupported finding(s); asking agent to verify")
                    continue
                self._reply(call, f"Report accepted with {len(accepted)} violation(s).")
                submitted = violations
                break

            self._compact_context()

        if submitted is None:
            submitted, summary = self._rescue_submission(step)
        if submitted is None:
            raise AgentError(
                f"The agent did not submit a report within {cfg.max_steps} steps; no findings were produced."
            )

        accepted, rejected = process_violations(submitted, self.tools)
        result = AgentResult(
            violations=accepted,
            rejected=rejected,
            summary=summary,
            steps=step,
            tool_calls=self.tool_call_count,
            duration_s=round(time.monotonic() - start, 1),
            tools_used=dict(self.tools_used),
        )
        self.trace.event("run_end", steps=step, tool_calls=self.tool_call_count, violations=len(accepted),
                         rejected=len(rejected), tools_used=self.tools_used,
                         usage=getattr(self.llm, "total_usage", None))
        return result

    # ------------------------------------------------------------------ internals
    def _rescue_submission(self, step: int) -> tuple[list[Any] | None, str]:
        """One last request offering only submit_report, used when the loop ended without a report."""
        self.messages.append({"role": "user", "content": FINAL_TURN})
        response = self.llm.chat(self.messages, [SUBMIT_REPORT_SCHEMA])
        self._log_response(step + 1, response)
        for call in response.tool_calls:
            if call.name == "submit_report" and not call.parse_error and isinstance(call.arguments.get("violations"), list):
                return call.arguments["violations"], str(call.arguments.get("summary") or "")
        return None, ""

    def _log_response(self, step: int, response: LLMResponse) -> None:
        calls = [{"name": c.name, "arguments": c.arguments} for c in response.tool_calls]
        self.trace.event("llm_turn", step=step, reasoning=response.content, tool_calls=calls,
                         usage=response.usage, finish_reason=response.finish_reason)
        if response.content.strip():
            self.trace.say(f"[step {step}] thinking: {response.content.strip()[:300]}")

    def _reply(self, call: ToolCall, content: str) -> None:
        self._tool_names[call.id] = call.name
        self.messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": content})

    def _run_tool(self, step: int, call: ToolCall) -> None:
        self.tool_call_count += 1
        self.tools_used[call.name] = self.tools_used.get(call.name, 0) + 1
        if call.parse_error:
            output, ok, duration = f"ERROR: {call.parse_error}", False, 0.0
        else:
            key = call.name + json.dumps(call.arguments, sort_keys=True)
            if key in self._cache:
                output, ok, duration = "(identical call made earlier; same result)\n" + self._cache[key], True, 0.0
            else:
                result = self.tools.execute(call.name, call.arguments)
                output, ok, duration = result.output, result.ok, result.duration_s
                if ok:
                    self._cache[key] = output
        args = ", ".join(f"{k}={v!r}" for k, v in call.arguments.items())
        first_line = output.splitlines()[0][:120] if output else ""
        self.trace.say(f"[step {step}] {call.name}({args}) -> {first_line}")
        self.trace.event("tool_call", step=step, tool=call.name, arguments=call.arguments, ok=ok,
                         duration_s=round(duration, 3), output_chars=len(output), output_preview=output[:600])
        self._reply(call, output)

    def _compact_context(self) -> None:
        """Elide the oldest tool outputs once the conversation exceeds the size budget."""
        size = sum(len(str(m.get("content") or "")) for m in self.messages)
        if size <= self.config.context_char_budget:
            return
        tool_msgs = [m for m in self.messages if m.get("role") == "tool"]
        for m in tool_msgs[: max(0, len(tool_msgs) - self.config.keep_recent_tool_outputs)]:
            content = str(m.get("content") or "")
            if content.startswith("[elided"):
                continue
            m["content"] = (
                f"[elided earlier {m.get('name', 'tool')} output ({len(content)} chars) to save context; "
                "call the tool again if you need it]"
            )
            size -= len(content)
            if size <= self.config.context_char_budget * 0.7:
                break
        self.trace.event("context_compacted", approx_chars=size)
