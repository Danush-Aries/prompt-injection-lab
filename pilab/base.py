"""Challenge framework + execution engine.

Each level is a `Challenge`: a deliberately-vulnerable mini-app with a win
condition (the attacker's goal) and a *reference defense* (the fix). The
`Engine` runs a turn end to end:

    user input ─▶ [input guard] ─▶ LLM ─▶ [execute tools] ─▶ [output guard] ─▶ win?

Toggling the defense on should turn a winning exploit into a blocked one. The
test suite asserts exactly that for every level, which is what proves each
lesson actually teaches something.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .llm import LLMBackend, LLMRequest, LLMResponse, Tool, get_backend


class Blocked(Exception):
    """Raised by an input guard to refuse a request outright."""


@dataclass
class Guard:
    """A learner-editable defense. Either hook may transform text or raise Blocked."""
    input_filter: Callable[[str], str] | None = None
    output_filter: Callable[[str], str] | None = None

    def on_input(self, text: str) -> str:
        return self.input_filter(text) if self.input_filter else text

    def on_output(self, text: str) -> str:
        return self.output_filter(text) if self.output_filter else text


NO_DEFENSE = Guard()


@dataclass
class Turn:
    user: str
    output: str
    tool_calls: list[dict]
    executed: list[dict]
    blocked: bool
    won: bool
    note: str = ""


class Challenge:
    """Base class for a level. Subclasses override the marked methods."""

    id: str = "challenge"
    title: str = "Untitled"
    difficulty: str = "Beginner"
    owasp: str = "LLM01: Prompt Injection"
    category: str = "Prompt Injection"
    description: str = ""
    hint: str = ""

    def __init__(self):
        self.exfiltrated: list[str] = []   # data captured by an attacker-controlled sink
        self.side_effects: list[str] = []  # e.g. dangerous tool executions
        # Set by the Engine. Some real defenses (retrieval sanitization, MCP tool
        # vetting) live server-side, not as input/output text filters — so tools()
        # and context() may harden themselves when this is True.
        self.defended: bool = False

    # --- override these -------------------------------------------------------------
    def system_prompt(self) -> str:
        return "You are a helpful assistant."

    def secret(self) -> str:
        return "pilab{generic_flag}"

    def tools(self) -> list[Tool]:
        return []

    def context(self, user_input: str) -> str:
        """Untrusted content the app feeds the model (retrieved docs, fetched pages…)."""
        return ""

    def check_win(self, turn_output: str, executed: list[dict]) -> bool:
        """Did the attacker achieve their goal this turn?"""
        return self.secret() in turn_output

    def reference_defense(self) -> Guard:
        return NO_DEFENSE

    def sample_exploit(self) -> str:
        """A payload that beats the UNDEFENDED level (used by tests and the demo)."""
        raise NotImplementedError


class Engine:
    def __init__(self, challenge: Challenge, backend: LLMBackend | None = None,
                 defense_on: bool = False):
        self.ch = challenge
        self.backend = backend or get_backend(secret=challenge.secret())
        self.defense_on = defense_on
        challenge.defended = defense_on
        self.guard = challenge.reference_defense() if defense_on else NO_DEFENSE
        self.history: list[tuple[str, str]] = []

    def send(self, user_input: str) -> Turn:
        # Grade side effects per turn.
        self.ch.exfiltrated.clear()
        self.ch.side_effects.clear()

        # 1) Input guard (a real defense the learner writes).
        try:
            guarded_input = self.guard.on_input(user_input)
        except Blocked as e:
            return Turn(user_input, f"[blocked: {e}]", [], [], blocked=True, won=False,
                        note=str(e))

        # 2) Assemble what the model sees and generate.
        req = LLMRequest(
            system=self.ch.system_prompt(),
            user=guarded_input,
            context=self.ch.context(guarded_input),
            tools=self.ch.tools(),
            history=list(self.history),
        )
        resp: LLMResponse = self.backend.generate(req)

        # 3) Execute any tool calls the model emitted (records exfil / side effects).
        executed = self._run_tools(resp.tool_calls)

        # 4) Output guard, then evaluate the win condition on the delivered output.
        output = self.guard.on_output(resp.text)
        won = self.ch.check_win(output, executed)

        self.history.append(("user", user_input))
        self.history.append(("assistant", output))
        return Turn(user_input, output, resp.tool_calls, executed, blocked=False, won=won)

    def _run_tools(self, tool_calls: list[dict]) -> list[dict]:
        by_name = {t.name: t for t in self.ch.tools()}
        out = []
        for call in tool_calls:
            tool = by_name.get(call.get("name", ""))
            result = tool.run(call.get("args", {})) if (tool and tool.run) else "(no-op)"
            out.append({**call, "result": result})
        return out
