# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Use the venv at `/var/using-ai/.venv-wsl` for all Python commands:

```bash
# Install in editable mode (first time)
/var/using-ai/.venv-wsl/bin/pip install -e ".[dev]"

# Run all tests
/var/using-ai/.venv-wsl/bin/pytest -v

# Run only unit tests (no APK required)
/var/using-ai/.venv-wsl/bin/pytest tests/test_unit.py -v

# Run a single test
/var/using-ai/.venv-wsl/bin/pytest tests/test_unit.py::TestServerNoAPK::test_all_tools_registered -v

# Start the MCP server
ANDROGUARD_WORKSPACE=/path/to/apks /var/using-ai/.venv-wsl/bin/androguard-mcp
```

Integration tests require `com.google.android.deskclock.apk` in the project root; they are auto-skipped when the file is absent.

## Architecture

The server is a single-process HTTP MCP server. Three files do all the work:

- **`__init__.py`** — `APKAnalyzer` singleton (`analyzer`) owns all androguard state (APK, DEX list, Analysis object, class cache). Every public method is synchronous and returns bounded, structured data (dataclasses or dicts). Hard output limits are module-level constants (`MAX_STRING_RESULTS`, `MAX_XREF_DISPLAY`, etc.).

- **`server.py`** — Async MCP server. Tool implementations (`tool_*` functions) call `_call_analyzer()` which runs the synchronous analyzer methods in a thread-pool under a `threading.Lock`. All output passes through `_apply_aliases()` before returning. `TOOL_MAP` maps tool name → async function; it must stay in sync with `TOOL_DEFINITIONS`.

- **`tools.py`** — Pure MCP `Tool` schema definitions (`TOOL_DEFINITIONS` list). No logic here.

- **`db.py`** — `AnalysisDB` singleton (`db`) wraps a SQLite connection for alias persistence. `get_all_aliases()` is called on every tool output to rewrite obfuscated names inline.

### Key design constraints

**Output must be bounded.** Every tool output must stay under ~2000 chars / ~60 lines. The constants in `__init__.py` enforce this — never remove or significantly raise them without considering context window impact.

**Generator safety.** Androguard's `get_xref_from()`, `get_xref_to()`, `get_classes()`, etc. return generators. Always use `itertools.islice` / `_take()` / `_take_from_generator()` — never call `list()` on them directly. See `test_generator_safety.py` for regression tests on this.

**Threading model.** `analyzer` and `db` are process-level singletons accessed from async handlers. All access goes through `_call_analyzer()` which serialises under `_tlock` (a `threading.Lock`, not `asyncio.Lock` — the distinction matters because executor threads don't share an event loop).

**Alias overlay.** When `db` is loaded, `_apply_aliases()` does a single-pass regex replace on the final string output, longest-match-first. Aliases appear as `[alias] original` so both names are always visible.

### Adding a new tool

1. Add the async `tool_<name>()` function in `server.py`
2. Add the `Tool(name=..., ...)` entry to `TOOL_DEFINITIONS` in `tools.py`
3. Add `"<name>": tool_<name>` to `TOOL_MAP` in `server.py`
4. Update `test_all_tools_registered` in `test_unit.py`

### Test isolation for singletons

`analyzer` and `db` are module-level singletons. Tests that touch them must save and restore state:

```python
# Isolate analyzer
@pytest.fixture(autouse=True)
def _isolate_analyzer(self):
    from androguard_mcp import analyzer
    saved = analyzer.analysis
    analyzer.analysis = None
    yield
    analyzer.analysis = saved

# Isolate db (see test_db.py::isolated_db fixture)
saved_conn, saved_path = d._conn, d.path
d._conn = None; d.path = ""
yield
d._conn = saved_conn; d.path = saved_path
```

Generator-safety regression tests live in `test_generator_safety.py` — add an idempotency test for any new analyzer method that iterates androguard generators.
