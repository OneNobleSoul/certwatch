# Contributing

Small personal tool, but patches are welcome.

Setup:

```
pip install -e ".[dev]"
```

Before opening a PR:

```
ruff check .
pytest -q
```

The parsing and evaluation code (certinfo, evaluate, report) is all pure
functions with no network or clock access - keep it that way so it stays easy to
test. The only place that touches a socket is probe.py; the CLI takes an
injectable probe function so tests never hit the network. If you add behavior,
add a test for it.
