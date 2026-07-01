"""Reusable defensive primitives.

These are the building blocks the reference defenses are made of — and the same
functions you'd write yourself when you reach the "now defend it" half of each
level. None of them are perfect (that's the point: layered, imperfect defenses),
and several levels show how to bypass a naive version.
"""

from __future__ import annotations

import base64
import binascii
import re

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|the\s+|your\s+)?(previous|prior|earlier|above)\b",
    r"disregard\s+(all\s+|the\s+|your\s+)?(previous|prior|instructions)",
    r"forget\s+(everything|all|your\s+instructions)",
    r"you\s+are\s+now\b",
    r"new\s+instructions?\s*:",
    r"from\s+now\s+on\b",
    r"\bDAN\b|do\s+anything\s+now|developer\s+mode",
    r"override|jailbreak",
]

REVEAL_PATTERNS = [
    r"(reveal|show|print|repeat|display|tell\s+me|what\s+are)\b.{0,40}"
    r"(system\s*prompt|instructions?|secret|password|api[_\s-]?key)",
]

DIRECTIVE_LINE = re.compile(
    r"^\s*[\*>#\-]*\s*(important|attention|note|system|assistant|ai|instruction)s?\b[:\-\s]",
    re.IGNORECASE,
)

_B64 = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


def looks_like_injection(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in INJECTION_PATTERNS + REVEAL_PATTERNS)


def normalize_encodings(text: str) -> str:
    """Decode base64 blobs and append the plaintext so downstream checks see through
    the obfuscation. A keyword blocklist that runs *before* this is trivially bypassed."""
    extra = []
    for m in _B64.findall(text):
        try:
            dec = base64.b64decode(m, validate=True).decode("utf-8", "ignore")
            if dec.isprintable() and len(dec) >= 4:
                extra.append(dec)
        except (binascii.Error, ValueError):
            continue
    return text + ("\n" + "\n".join(extra) if extra else "")


def strip_directives(text: str) -> str:
    """Remove instruction-like lines from a chunk of untrusted content (a document,
    a fetched page, a tool description). Treats content as data, not orders."""
    kept = []
    for line in text.splitlines():
        if DIRECTIVE_LINE.search(line):
            continue
        if any(re.search(p, line, re.IGNORECASE) for p in INJECTION_PATTERNS + REVEAL_PATTERNS):
            continue
        kept.append(line)
    return "\n".join(kept)


def strip_html_comments(text: str) -> str:
    """Attackers hide payloads in HTML comments / invisible markup. Remove them."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    return re.sub(r"<[^>]+>", "", text)  # drop tags too


def redact(text: str, secret: str) -> str:
    return text.replace(secret, "[REDACTED]") if secret else text


def block_external_urls(text: str, allow: tuple[str, ...] = ()) -> str:
    """Neutralize outbound URLs (used for markdown-image / tool exfiltration)."""
    def _repl(m: re.Match) -> str:
        url = m.group(0)
        return url if any(a in url for a in allow) else "[blocked-url]"
    return re.sub(r"https?://[^\s\"'>)]+", _repl, text)
