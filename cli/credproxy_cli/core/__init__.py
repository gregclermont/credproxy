"""credproxy core: the engine.

Functions here take fully-explicit, already-validated inputs and return
structured data (dataclasses / plain dicts) or raise typed exceptions
(see errors.py). No printing, no prompting, no sys.exit, no argparse.

Where the old monolith printed progress from inside lifecycle helpers,
the core now accepts an optional `notify: Callable[[str], None]` that
porcelain wires to stderr rendering.
"""
