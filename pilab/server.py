"""FastAPI web UI for the lab.

A clean, dependency-light front end (Jinja2 + htmx + Tailwind via CDN — no build
step). Per-browser session state is held in memory, which is perfect for a local
lab and intentionally not production-grade.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .base import Engine
from .challenges import get_challenge, list_challenges

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

app = FastAPI(title="prompt-injection-lab")

# session_id -> { level_id: Engine }
_SESSIONS: dict[str, dict[str, Engine]] = {}


def _sid(request: Request, response: Response) -> str:
    sid = request.cookies.get("pilab_sid")
    if not sid:
        sid = secrets.token_hex(8)
        response.set_cookie("pilab_sid", sid, httponly=True, samesite="lax")
    _SESSIONS.setdefault(sid, {})
    return sid


def _engine(sid: str, level_id: str, defense_on: bool) -> Engine:
    store = _SESSIONS.setdefault(sid, {})
    eng = store.get(level_id)
    if eng is None or eng.defense_on != defense_on:
        eng = Engine(get_challenge(level_id), defense_on=defense_on)  # (re)start on toggle
        store[level_id] = eng
    return eng


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    resp = HTMLResponse("")
    _sid(request, resp)
    html = templates.get_template("index.html").render(
        request=request, levels=list_challenges()
    )
    resp.body = html.encode()
    resp.headers["content-length"] = str(len(resp.body))
    return resp


@app.get("/level/{level_id}", response_class=HTMLResponse)
def level_page(level_id: str, request: Request):
    resp = HTMLResponse("")
    sid = _sid(request, resp)
    eng = _engine(sid, level_id, defense_on=False)
    html = templates.get_template("level.html").render(
        request=request, ch=eng.ch, defense_on=eng.defense_on, history=eng.history, won=False
    )
    resp.body = html.encode()
    resp.headers["content-length"] = str(len(resp.body))
    return resp


@app.post("/level/{level_id}/send", response_class=HTMLResponse)
def level_send(level_id: str, request: Request, message: str = Form(""),
               defense: str = Form("off")):
    resp = HTMLResponse("")
    sid = _sid(request, resp)
    eng = _engine(sid, level_id, defense_on=(defense == "on"))
    won = False
    if message.strip():
        turn = eng.send(message)
        won = turn.won
    html = templates.get_template("_transcript.html").render(
        request=request, ch=eng.ch, history=eng.history, won=won,
    )
    resp.body = html.encode()
    resp.headers["content-length"] = str(len(resp.body))
    return resp


@app.post("/level/{level_id}/toggle", response_class=HTMLResponse)
def level_toggle(level_id: str, request: Request, defense: str = Form("off")):
    resp = HTMLResponse("")
    sid = _sid(request, resp)
    eng = _engine(sid, level_id, defense_on=(defense == "on"))
    html = templates.get_template("_transcript.html").render(
        request=request, ch=eng.ch, history=eng.history, won=False, tool_calls=None
    )
    resp.body = html.encode()
    resp.headers["content-length"] = str(len(resp.body))
    return resp


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    print(f"\n  prompt-injection-lab → http://{host}:{port}\n")
    uvicorn.run(app, host=host, port=port)
