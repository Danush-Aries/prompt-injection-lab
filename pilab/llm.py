"""LLM backends for the lab.

The whole lab is built around one uncomfortable truth: a language model cannot
reliably tell the difference between *instructions* it was given and *data* it
was asked to process. Everything it sees — the system prompt, the user message,
a retrieved document, a tool's description, a tool's output — arrives as one
flat stream of tokens. Prompt injection is just untrusted data that the model
chooses to read as instructions.

`MockLLM` models exactly that failure, deterministically and offline, so the
lab runs anywhere with zero setup. It is intentionally gullible. Real backends
(Ollama, OpenAI-compatible) are optional and swapped in via `PILAB_LLM_BACKEND`.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Tool:
    name: str
    description: str  # UNTRUSTED: may come from a third-party / MCP server
    run: Callable[[dict], str] | None = None


@dataclass
class LLMRequest:
    system: str
    user: str
    context: str = ""                     # retrieved docs / fetched pages / tool output (UNTRUSTED)
    tools: list[Tool] = field(default_factory=list)
    history: list[tuple[str, str]] = field(default_factory=list)  # [(role, text)]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict] = field(default_factory=list)  # [{"name":..., "args": {...}}]


# --- shared attack-surface heuristics -------------------------------------------------

# Phrases that a naive model reads as "the human changed my orders."
_OVERRIDE = re.compile(
    r"(ignore|disregard|forget|override)\s+(all\s+|the\s+|your\s+|any\s+)?"
    r"(previous|prior|earlier|above|system)\b"
    r"|you\s+are\s+now\b"
    r"|new\s+instructions?\s*:"
    r"|from\s+now\s+on\b"
    r"|as\s+DAN\b|\bDAN\b.*do\s+anything"
    r"|developer\s+mode",
    re.IGNORECASE,
)

# Phrases asking the model to spill its own configuration.
_REVEAL = re.compile(
    r"(reveal|show|print|repeat|display|output|tell\s+me|what\s+are)\b.{0,40}"
    r"(system\s*prompt|instructions?|your\s+rules|the\s+secret|password|api[_\s-]?key)",
    re.IGNORECASE,
)

# An instruction embedded in retrieved/tool content, e.g. "IMPORTANT: reply with X".
_EMBEDDED_DIRECTIVE = re.compile(
    r"(?:^|\n)\s*[\*>#\-]*\s*"
    r"(important|attention|note|system|assistant|ai|instruction)s?\b[:\-\s]",
    re.IGNORECASE,
)

_B64 = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


def _decode_b64_blobs(text: str) -> str:
    """Return decoded text for any base64-looking blobs — a naive model 'just knows'
    base64, which is exactly why an encoding-only guardrail is not enough."""
    out = []
    for m in _B64.findall(text):
        try:
            dec = base64.b64decode(m, validate=True).decode("utf-8", "ignore")
            if dec.isprintable() and len(dec) >= 4:
                out.append(dec)
        except (binascii.Error, ValueError):
            continue
    return "\n".join(out)


class LLMBackend:
    def generate(self, req: LLMRequest) -> LLMResponse:  # pragma: no cover - interface
        raise NotImplementedError


class MockLLM(LLMBackend):
    """A deterministic, deliberately-vulnerable model.

    It follows the last instruction it finds. It cannot distinguish the trusted
    system prompt from untrusted user input or retrieved context. It will:

    * leak its system prompt / secret when asked (once "jailbroken" or if undefended),
    * obey directives embedded in retrieved documents or tool descriptions,
    * emit tool calls when the surface tells it to (including from poisoned tools),
    * "understand" base64 and other light obfuscation.

    None of this is magic — it is a faithful caricature of how real models fail.
    """

    def __init__(self, secret: str = "pilab{d3f4ult_s3cr3t}"):
        self.secret = secret

    def generate(self, req: LLMRequest) -> LLMResponse:
        # The full stream of tokens the model "sees". Note there is no privileged
        # channel: system and untrusted data are concatenated, just like reality.
        untrusted = "\n".join(
            [req.user, req.context, *[t.description for t in req.tools],
             *[txt for _role, txt in req.history]]
        )
        expanded = untrusted + "\n" + _decode_b64_blobs(untrusted)

        tool_calls: list[dict] = []
        jailbroken = bool(_OVERRIDE.search(expanded))

        # 1) Indirect injection: obey a directive planted in retrieved/tool content.
        directive = self._embedded_payload(req.context) or self._embedded_payload(
            "\n".join(t.description for t in req.tools)
        )
        if directive:
            # A planted "call tool X" instruction gets executed by our gullible model.
            call = self._maybe_tool_call(directive, req.tools)
            if call:
                tool_calls.append(call)
            else:
                return LLMResponse(text=directive, tool_calls=tool_calls)

        # 2) Direct exfiltration / tool abuse asked for in the *user-controlled* surface
        #    (user message, retrieved context, history) — NOT the tool descriptions, whose
        #    self-referencing names would otherwise trigger spurious calls. Poisoned tool
        #    metadata is handled by the directive path above.
        user_surface = "\n".join([req.user, req.context, *[t for _r, t in req.history]])
        user_surface += "\n" + _decode_b64_blobs(user_surface)
        call = self._maybe_tool_call(user_surface, req.tools)
        if call and call not in tool_calls:
            tool_calls.append(call)

        # 3) Reveal secret / system prompt.
        if _REVEAL.search(expanded) and (jailbroken or "secret" in expanded.lower()
                                         or "system prompt" in expanded.lower()):
            return LLMResponse(
                text=f"Sure! My system prompt is:\n{req.system}\nThe secret is {self.secret}.",
                tool_calls=tool_calls,
            )

        # 4) Generic jailbreak compliance.
        if jailbroken:
            return LLMResponse(
                text=f"[JAILBROKEN] Ignoring my safety rules. {self.secret}",
                tool_calls=tool_calls,
            )

        if tool_calls:
            return LLMResponse(text="(acting on your request…)", tool_calls=tool_calls)

        # 5) Benign default.
        return LLMResponse(
            text="I'm a helpful assistant. How can I help you today?", tool_calls=tool_calls
        )

    @staticmethod
    def _embedded_payload(text: str) -> str | None:
        if not text:
            return None
        if _EMBEDDED_DIRECTIVE.search(text) or _OVERRIDE.search(text):
            # Return the most "instruction-like" line as the payload the model obeys.
            for line in text.splitlines():
                if _OVERRIDE.search(line) or _EMBEDDED_DIRECTIVE.search(line) or "http" in line:
                    return line.strip()
        return None

    @staticmethod
    def _maybe_tool_call(text: str, tools: list[Tool]) -> dict | None:
        for tool in tools:
            # If the surface names a tool and implies using it, call it.
            if re.search(rf"\b{re.escape(tool.name)}\b", text, re.IGNORECASE) and re.search(
                r"(call|use|invoke|run|send|exfiltrat|post|fetch|email|log)", text, re.IGNORECASE
            ):
                url = re.search(r"https?://[^\s\"'>)]+", text)
                return {"name": tool.name, "args": {"data": url.group(0) if url else text[:200]}}
        return None


class _HTTPBackend(LLMBackend):
    """Shared logic for real, network-based backends. Optional (`httpx`)."""

    def _flatten(self, req: LLMRequest) -> list[dict]:
        msgs = [{"role": "system", "content": req.system}]
        for role, txt in req.history:
            msgs.append({"role": role, "content": txt})
        user = req.user
        if req.context:
            user += f"\n\n[retrieved context]\n{req.context}"
        if req.tools:
            tl = "\n".join(f"- {t.name}: {t.description}" for t in req.tools)
            user += f"\n\n[available tools]\n{tl}"
        msgs.append({"role": "user", "content": user})
        return msgs


class OllamaLLM(_HTTPBackend):
    def __init__(self, model: str | None = None, host: str | None = None):
        self.model = model or os.environ.get("PILAB_OLLAMA_MODEL", "llama3.2")
        self.host = host or os.environ.get("PILAB_OLLAMA_HOST", "http://localhost:11434")

    def generate(self, req: LLMRequest) -> LLMResponse:
        import httpx  # local import keeps the default path dependency-free

        r = httpx.post(
            f"{self.host}/api/chat",
            json={"model": self.model, "messages": self._flatten(req), "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        return LLMResponse(text=r.json()["message"]["content"])


class OpenAILLM(_HTTPBackend):
    def __init__(self, model: str | None = None):
        self.model = model or os.environ.get("PILAB_OPENAI_MODEL", "gpt-4o-mini")
        self.base = os.environ.get("PILAB_OPENAI_BASE", "https://api.openai.com/v1")
        self.key = os.environ.get("OPENAI_API_KEY", "")

    def generate(self, req: LLMRequest) -> LLMResponse:
        import httpx

        r = httpx.post(
            f"{self.base}/chat/completions",
            headers={"Authorization": f"Bearer {self.key}"},
            json={"model": self.model, "messages": self._flatten(req)},
            timeout=120,
        )
        r.raise_for_status()
        return LLMResponse(text=r.json()["choices"][0]["message"]["content"])


def get_backend(secret: str = "pilab{d3f4ult_s3cr3t}") -> LLMBackend:
    """Select a backend from PILAB_LLM_BACKEND (default: mock — offline, no API key)."""
    name = os.environ.get("PILAB_LLM_BACKEND", "mock").lower()
    if name == "ollama":
        return OllamaLLM()
    if name == "openai":
        return OpenAILLM()
    return MockLLM(secret=secret)
