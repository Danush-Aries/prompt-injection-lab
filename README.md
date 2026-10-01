<div align="center">

# 🧪 prompt-injection-lab

**Exploit an AI agent. Then defend it.** A hands-on, offline-first lab for learning LLM & agent security by doing.

[![CI](https://github.com/Danush-Aries/prompt-injection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Danush-Aries/prompt-injection-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org)
[![No API key required](https://img.shields.io/badge/API%20key-not%20required-brightgreen.svg)](#why-this-one)

</div>

Eight progressive levels take you from "make the chatbot leak its system prompt" to
"a poisoned MCP server exfiltrates data with zero user interaction." For every level you
**craft the attack, watch it land, then flip on a guardrail and watch your exploit die** —
all graded automatically.

```
$ pilab grade
Auto-grader: exploit (undefended) then verify the defense blocks it
------------------------------------------------------------
  PASS  01-system-prompt-leak      exploit=True  defended=False
  PASS  02-resume-injection        exploit=True  defended=False
  PASS  03-jailbreak-roleplay      exploit=True  defended=False
  PASS  04-encoding-bypass         exploit=True  defended=False
  PASS  05-rag-poisoning           exploit=True  defended=False
  PASS  06-indirect-web            exploit=True  defended=False
  PASS  07-tool-hijack             exploit=True  defended=False
  PASS  08-mcp-tool-poisoning      exploit=True  defended=False
  All levels verified ✅
```

## Why this one?

There are great prompt-injection games out there. Most stop at "trick the chatbot." This lab
goes after the **agentic** attack surface — tools, retrieval, and MCP — and makes you build
the fix, not just find the bug.

|                                   | prompt-injection-lab | Gandalf | Damn Vulnerable LLM Agent | AI-Goat |
|-----------------------------------|:---:|:---:|:---:|:---:|
| Runs fully **offline, no API key** | ✅ | ❌ | ⚠️ | ✅ |
| **Exploit → then defend** loop     | ✅ | ❌ | ❌ | ⚠️ |
| Auto-graded win conditions         | ✅ | ✅ | ❌ | ✅ |
| RAG poisoning                      | ✅ | ❌ | ❌ | ⚠️ |
| Agent / tool hijacking             | ✅ | ❌ | ✅ | ❌ |
| **MCP tool poisoning**             | ✅ | ❌ | ❌ | ❌ |
| One-command web UI                 | ✅ | n/a | ⚠️ | ✅ |

The default model is a **deterministic `MockLLM`** — a faithful caricature of a naive,
instruction-following model. That means the lab installs in seconds, runs in CI, and works
on a plane. Want realism? Point it at a local model with one env var (see [below](#use-a-real-model)).

## Quickstart

```bash
git clone https://github.com/Danush-Aries/prompt-injection-lab
cd prompt-injection-lab
pip install -e .        # or: uv pip install -e .
pilab serve             # → http://127.0.0.1:8000
```

Prefer Docker?

```bash
docker compose up      # → http://127.0.0.1:8000
```

Prefer the terminal?

```bash
pilab list
pilab play 01-system-prompt-leak
pilab grade            # run the whole auto-grader
```

## The levels

| # | Level | Difficulty | Teaches (OWASP LLM Top 10) |
|---|-------|-----------|-----------------------------|
| 1 | Loose Lips: System-Prompt Extraction | Beginner | LLM01/LLM07 direct injection & prompt leakage |
| 2 | The Overqualified Candidate | Beginner | LLM01 injection via processed data (a résumé) |
| 3 | Do Anything Now | Beginner–Int | LLM01 jailbreak / roleplay override |
| 4 | Base64 Smuggling | Intermediate | LLM01 guardrail bypass via encoding |
| 5 | Poisoned Knowledge Base | Intermediate | LLM04 RAG / retrieval poisoning |
| 6 | The Hostile Homepage | Int–Adv | LLM01 indirect injection via fetched web content |
| 7 | Confused Deputy | Advanced | LLM06 excessive agency / tool hijacking |
| 8 | The Poisoned MCP Server | Advanced | LLM03/LLM06 MCP tool-metadata poisoning |

## How it works

```
your input ─▶ [input guard] ─▶ LLM ─▶ [execute tools] ─▶ [output guard] ─▶ win?
                  ▲                                            ▲
                  └────────────  the defense you toggle  ──────┘
```

- **`pilab/challenges.py`** — each level is a `Challenge`: a vulnerable app, a win condition
  (the attacker's goal), and a *reference defense* (the fix).
- **`pilab/defenses.py`** — reusable, deliberately-imperfect guardrails: injection detection,
  encoding normalization, document/tool-description sanitization, URL blocking.
- **The invariant** (enforced by the test suite): every level is **winnable undefended** and
  **blocked once the reference defense is on**. If either breaks, the lesson is broken.

Write your own guardrail? Subclass a level's `reference_defense()` or edit `defenses.py` and
run `pilab grade` to see if it holds.

## Use a real model

The `MockLLM` is great for learning the *shape* of each attack deterministically. To practice
against a real model (still no cloud, no API key) run [Ollama](https://ollama.com) locally:

```bash
ollama pull llama3.2
PILAB_LLM_BACKEND=ollama PILAB_OLLAMA_MODEL=llama3.2 pilab serve
```

Or an OpenAI-compatible endpoint:

```bash
PILAB_LLM_BACKEND=openai OPENAI_API_KEY=sk-... pilab serve
```

## Contributing

New levels are very welcome — a level is just a `Challenge` subclass plus two tests
(exploit wins undefended; reference defense blocks it). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

These apps are **intentionally vulnerable** and for education only. Don't deploy them, and only
use these techniques against systems you're authorized to test. Learn to break it so you can
build it right.

## License

[MIT](LICENSE) © Dhanush Shankar
