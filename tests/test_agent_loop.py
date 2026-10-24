import json

import pytest

from auditor.agent_loop import AgentConfig, AgentError, AuditAgent
from auditor.trace import TraceLogger
from tests.conftest import FakeLLM, violation
from tools import RepoTools

AWS = "AKIA" + "Q3EGRTZXMPLW7Y2B"


def make_agent(repo, turns, max_steps=10, trace=None):
    llm = FakeLLM(turns)
    tools = RepoTools(repo, "main")
    agent = AuditAgent(llm, tools, "https://github.com/o/r", AgentConfig(max_steps=max_steps), trace)
    return agent, llm


def test_llm_directs_tool_calls_and_follow_ups(repo_factory):
    repo = repo_factory({"README.md": "# demo\n", "config.py": f"DEBUG = True\nAPI_KEY = '{AWS}'\n"})
    agent, llm = make_agent(repo, [
        [("list_files", {})],
        [("search_code", {"pattern": "API_KEY"})],
        [("read_file", {"path": "config.py"})],  # follow-up chosen from the previous result
        [("submit_report", {"summary": "one issue", "violations": [violation()]})],
    ])
    result = agent.run()
    assert [v["rule_id"] for v in result.violations] == ["SEC-001"]
    assert result.tools_used == {"list_files": 1, "search_code": 1, "read_file": 1}
    # The tool results were fed back to the LLM, with the secret masked.
    tool_msgs = [m for m in llm.calls[-1]["messages"] if m["role"] == "tool"]
    assert len(tool_msgs) == 3
    assert all(AWS not in m["content"] for m in tool_msgs)
    assert "config.py:2:" in tool_msgs[1]["content"]


def test_parallel_tool_calls_in_one_turn(repo_factory):
    repo = repo_factory({"a.py": "x = 1\n", "b.py": "y = 2\n"})
    agent, _ = make_agent(repo, [
        [("read_file", {"path": "a.py"}), ("read_file", {"path": "b.py"})],
        [("submit_report", {"violations": []})],
    ])
    result = agent.run()
    assert result.tool_calls == 2 and result.violations == []


def test_unsupported_findings_get_one_verification_round(repo_factory):
    repo = repo_factory({"config.py": f"API_KEY = '{AWS}'\n", "README.md": "x\n"})
    claim = violation(line=1)
    agent, llm = make_agent(repo, [
        [("list_files", {})],
        [("submit_report", {"violations": [claim]})],  # line cited without reading the file
        [("read_file", {"path": "config.py"})],
        [("submit_report", {"violations": [claim]})],
    ])
    result = agent.run()
    assert len(result.violations) == 1
    feedback = [m for m in llm.calls[2]["messages"] if m["role"] == "tool"][-1]["content"]
    assert "not supported by evidence" in feedback


def test_still_unsupported_findings_are_discarded(repo_factory):
    repo = repo_factory({"config.py": "x = 1\n"})
    agent, _ = make_agent(repo, [
        [("submit_report", {"violations": [violation(file="nowhere.py")]})],
    ])
    result = agent.run()
    assert result.violations == [] and len(result.rejected) == 1


def test_bad_arguments_and_unknown_tools_are_reported_back(repo_factory):
    repo = repo_factory({"a.py": "x\n"})
    agent, llm = make_agent(repo, [
        [("read_file", "{not json"), ("delete_repo", {})],
        [("submit_report", {"violations": []})],
    ])
    agent.run()
    outputs = [m["content"] for m in llm.calls[1]["messages"] if m["role"] == "tool"]
    assert any("not valid JSON" in o or "ERROR" in o for o in outputs)
    assert any("unknown tool" in o for o in outputs)


def test_budget_forces_final_submission(repo_factory):
    repo = repo_factory({"a.py": "x\n"})
    agent, llm = make_agent(repo, [[("list_files", {})]] * 2 + [[("submit_report", {"violations": []})]],
                            max_steps=3)
    result = agent.run()
    assert result.steps == 3
    assert llm.calls[-1]["tools"] == ["submit_report"]  # only submit offered on the last turn
    assert any("budget is exhausted" in str(m.get("content")) for m in llm.calls[-1]["messages"])


def test_text_only_replies_are_nudged_then_fail_cleanly(repo_factory):
    repo = repo_factory({"a.py": "x\n"})
    agent, _ = make_agent(repo, ["hmm", "still thinking", "done", "bye"], max_steps=10)
    with pytest.raises(AgentError):
        agent.run()


def test_rescue_submission_after_text_only_replies(repo_factory):
    repo = repo_factory({"a.py": "x\n"})
    agent, _ = make_agent(repo, ["a", "b", "c", [("submit_report", {"violations": []})]])
    assert agent.run().violations == []


def test_trace_records_every_tool_call(repo_factory, tmp_path):
    repo = repo_factory({"a.py": "x\n"})
    trace_path = tmp_path / "t.jsonl"
    with TraceLogger(trace_path, console=None) as trace:
        agent, _ = make_agent(repo, [[("git_log", {})], [("submit_report", {"violations": []})]], trace=trace)
        agent.run()
    events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    kinds = [e["event"] for e in events]
    assert kinds[0] == "run_start" and kinds[-1] == "run_end"
    assert any(e["event"] == "tool_call" and e["tool"] == "git_log" for e in events)


def test_repeated_identical_call_is_cached(repo_factory):
    repo = repo_factory({"a.py": "x\n"})
    agent, llm = make_agent(repo, [[("list_files", {})], [("list_files", {})], [("submit_report", {"violations": []})]])
    agent.run()
    last = [m for m in llm.calls[-1]["messages"] if m["role"] == "tool"][-1]["content"]
    assert last.startswith("(identical call made earlier")
