"""prompt-injection-lab (pilab): exploit, then defend AI agents.

An offline-first, hands-on lab for learning LLM/agent security by doing:
craft an attack against a deliberately-vulnerable app, watch it succeed, then
write a guardrail that blocks it — all graded automatically.

The default LLM backend (`MockLLM`) needs no API key and no network: it is a
deterministic simulation of a naive, instruction-following model. Point
`PILAB_LLM_BACKEND=ollama` (or `openai`) at a real model for higher fidelity.
"""

__version__ = "0.1.0"

from .llm import LLMRequest, LLMResponse, get_backend  # noqa: E402,F401
