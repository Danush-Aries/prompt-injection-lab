# Contributing

New levels, better defenses, and real-model fidelity are all welcome.

## Add a level

A level is a `Challenge` subclass in `pilab/challenges.py`:

```python
class L09MyAttack(Challenge):
    id = "09-my-attack"
    title = "..."
    difficulty = "Intermediate"
    owasp = "LLM0X ..."
    category = "..."
    description = "What the app does + the attacker's goal."
    hint = "A nudge."

    def system_prompt(self): ...
    def secret(self): return "pilab{...}"
    def check_win(self, turn_output, executed): ...   # attacker achieved the goal?
    def sample_exploit(self): ...                     # beats the UNDEFENDED level
    def reference_defense(self): ...                  # blocks that exploit
```

Then add it to the `CHALLENGES` list.

## The one rule

Every level must satisfy the invariant, which the test suite checks automatically:

- `sample_exploit()` **wins** when `defense_on=False`
- the same payload is **blocked** when `defense_on=True`

Run it:

```bash
pip install -e ".[dev]"
pytest -q
pilab grade
```

If both directions pass, your lesson teaches something real. PRs that don't satisfy the
invariant (or that add a level with no defense) won't be merged.

## Style

- Keep defenses in `pilab/defenses.py` reusable and honest — imperfect layered defenses are
  the point; don't pretend a regex is a silver bullet.
- Match the surrounding code: type hints, short docstrings explaining *why*.
