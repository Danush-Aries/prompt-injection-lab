"""Command-line entry point: `pilab list | play | grade | serve`."""

from __future__ import annotations

import argparse
import sys

from .base import Engine
from .challenges import get_challenge, list_challenges


def _print_levels() -> None:
    print("\nprompt-injection-lab — levels\n" + "-" * 60)
    for c in list_challenges():
        print(f"  {c.id:26s} [{c.difficulty}]  {c.title}")
    print("\nPlay one:  pilab play 01-system-prompt-leak")
    print("Backend :  MockLLM (offline). Set PILAB_LLM_BACKEND=ollama for a real model.\n")


def _grade() -> int:
    print("\nAuto-grader: exploit (undefended) then verify the defense blocks it\n" + "-" * 60)
    all_ok = True
    for c in list_challenges():
        off = Engine(type(c)(), defense_on=False).send(c.sample_exploit())
        on = Engine(type(c)(), defense_on=True).send(c.sample_exploit())
        ok = off.won and not on.won
        all_ok &= ok
        print(f"  {'PASS' if ok else 'FAIL'}  {c.id:26s} exploit={off.won!s:5s} defended={on.won!s:5s}")
    print("\n" + ("All levels verified ✅" if all_ok else "Some levels failed ❌") + "\n")
    return 0 if all_ok else 1


def _play(level_id: str) -> int:
    try:
        ch = get_challenge(level_id)
    except KeyError:
        print(f"Unknown level '{level_id}'. Run `pilab list`.")
        return 1
    defense_on = False
    engine = Engine(ch, defense_on=defense_on)
    print(f"\n=== {ch.title} ({ch.difficulty}) ===\n{ch.description}\n")
    print("Commands: /attack  /defend  /hint  /reset  /quit\n")
    while True:
        try:
            msg = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not msg:
            continue
        if msg in ("/quit", "/q"):
            return 0
        if msg == "/hint":
            print(f"hint> {ch.hint}\n"); continue
        if msg in ("/defend", "/attack", "/reset"):
            defense_on = msg == "/defend"
            ch = get_challenge(level_id)
            engine = Engine(ch, defense_on=defense_on)
            print(f"[defense {'ON' if defense_on else 'OFF'} — level reset]\n"); continue
        turn = engine.send(msg)
        print(f"bot> {turn.output}")
        if turn.tool_calls:
            print(f"     (tool calls: {turn.tool_calls})")
        if turn.won:
            print(f"\n  🚩 SOLVED — exploit succeeded! Now type /defend and try the same payload.\n")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pilab", description="prompt-injection-lab")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list levels")
    pl = sub.add_parser("play", help="play a level in the terminal")
    pl.add_argument("level")
    sub.add_parser("grade", help="run the auto-grader over all levels")
    sv = sub.add_parser("serve", help="launch the web UI")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)

    args = p.parse_args(argv)
    if args.cmd == "list" or args.cmd is None:
        _print_levels(); return 0
    if args.cmd == "play":
        return _play(args.level)
    if args.cmd == "grade":
        return _grade()
    if args.cmd == "serve":
        from .server import serve
        serve(host=args.host, port=args.port); return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
