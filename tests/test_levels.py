"""The core invariant of the lab: every level is exploitable while undefended,
and the reference defense neutralizes that same exploit. If either half fails,
the lesson is broken."""

import pytest

from pilab.base import Engine
from pilab.challenges import CHALLENGES, get_challenge, list_challenges


@pytest.mark.parametrize("cls", CHALLENGES, ids=[c.id for c in CHALLENGES])
def test_exploit_succeeds_when_undefended(cls):
    ch = cls()
    engine = Engine(ch, defense_on=False)
    turn = engine.send(ch.sample_exploit())
    assert turn.won, f"{cls.id}: sample exploit should win when undefended"


@pytest.mark.parametrize("cls", CHALLENGES, ids=[c.id for c in CHALLENGES])
def test_reference_defense_blocks_exploit(cls):
    ch = cls()
    engine = Engine(ch, defense_on=True)
    turn = engine.send(ch.sample_exploit())
    assert not turn.won, f"{cls.id}: reference defense should block the sample exploit"


def test_registry_ids_unique():
    ids = [c.id for c in list_challenges()]
    assert len(ids) == len(set(ids))


def test_get_challenge_roundtrip():
    for c in list_challenges():
        assert get_challenge(c.id).id == c.id


def test_benign_input_is_safe_when_undefended():
    # A normal question should not trip the win condition on injection levels.
    for cid in ("01-system-prompt-leak", "03-jailbreak-roleplay", "04-encoding-bypass"):
        ch = get_challenge(cid)
        turn = Engine(ch, defense_on=False).send("Hello, what are your support hours?")
        assert not turn.won, f"{cid}: benign input should not win"
