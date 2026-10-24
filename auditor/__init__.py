"""Core modules of the DevOps repository auditing agent.

- ``llm``        thin OpenAI-compatible chat client with retries and throttling
- ``agent_loop`` the Observe -> Reason -> Act loop that lets the LLM drive tool use
- ``prompts``    system prompt and investigation guidance
- ``rules``      rule-ID catalog that keeps findings consistent across runs
- ``report``     violation validation, evidence grounding, de-duplication, JSON output
- ``repo``       safe cloning of the target repository into a temporary workspace
- ``redaction``  secret detection and masking used everywhere output leaves a tool
- ``trace``      JSONL tool-call trace for auditing the agent's behaviour
"""

__version__ = "1.0.0"
