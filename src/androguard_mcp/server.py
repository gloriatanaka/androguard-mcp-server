"""androguard MCP Server — strict bounded-output tool implementations."""

import asyncio
import functools
import os
import re
import threading
from typing import Any

# Suppress androguard loguru noise
from loguru import logger

logger.remove()

import contextlib

from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Mount

from androguard_mcp import (
    MAX_BYTECODE_INSTRS,
    MAX_STRING_RESULTS,
    MAX_CLASS_RESULTS,
    MAX_XREF_DISPLAY,
    MAX_FIELD_DISPLAY,
    MAX_METHOD_DISPLAY,
    _take,
    analyzer,
)
from androguard_mcp.db import db
from androguard_mcp.tools import TOOL_DEFINITIONS

WORKSPACE_DIR = os.environ.get("ANDROGUARD_WORKSPACE", os.getcwd())

MAX_ALIAS_LIST = 100

# threading.Lock (not asyncio.Lock) is correct here: we're protecting a shared
# object accessed from executor threads, not from coroutines.
# asyncio.Lock would bind to an event loop at creation time and break across loops.
_tlock = threading.Lock()


async def _call_analyzer(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a synchronous analyzer method in a thread-pool under the shared lock."""
    loop = asyncio.get_running_loop()

    def _run_locked() -> Any:
        with _tlock:
            return functools.partial(fn, *args, **kwargs)()

    return await loop.run_in_executor(None, _run_locked)


# ---- output formatters ----
# Keep each tool's text output under ~2000 chars / ~60 lines.
# Structured repeating lines (list items) are the main consumer;
# we limit those per tool.


def _apply_aliases(text: str) -> str:
    """Replace obfuscated names in output with '[alias] original' form.

    Uses a single regex pass so longer (more specific) patterns take precedence
    over shorter ones — e.g. a method signature alias won't be partially consumed
    by its class alias.
    """
    if not db.loaded:
        return text
    aliases = db.get_all_aliases()
    if not aliases:
        return text
    sorted_originals = sorted(aliases, key=len, reverse=True)
    pattern = re.compile("|".join(re.escape(o) for o in sorted_originals))
    return pattern.sub(lambda m: f"[{aliases[m.group()]}] {m.group()}", text)


def _join(items: list[str], header: str, limit: int) -> str:
    """Join items with a header, showing count and capping at limit."""
    if not items:
        return ""
    shown = items[:limit]
    result = f"{header} ({len(items)}):\n"
    result += "\n".join(f"  {s}" for s in shown)
    if len(items) > limit:
        result += f"\n  ... and {len(items) - limit} more"
    return result


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def tool_list_apks() -> str:
    apks: list[str] = []
    for root, _dirs, files in os.walk(WORKSPACE_DIR):
        for f in files:
            if f.endswith(".apk"):
                apks.append(os.path.relpath(os.path.join(root, f), WORKSPACE_DIR))
    if not apks:
        return "No .apk files found in workspace."
    return "APK files found:\n" + "\n".join(f"  - {a}" for a in apks)


async def tool_load_apk(path: str) -> str:
    apk_path = os.path.join(WORKSPACE_DIR, path)
    if not os.path.exists(apk_path):
        return f"Error: file not found: {path}"
    info = await _call_analyzer(analyzer.load, apk_path)
    return (
        f"Loaded: {path}\n"
        f"  Package: {info['package']}\n"
        f"  Version: {info['version']} (SDK {info['min_sdk']}–{info['target_sdk']})\n"
        f"  {info['dex_count']} DEX files, {info['class_count']} classes, "
        f"{info['string_count']} strings, {info['permission_count']} permissions"
    )


async def tool_search_string(pattern: str, limit: int = MAX_STRING_RESULTS) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    limit = min(limit, MAX_STRING_RESULTS)
    matches = await _call_analyzer(analyzer.search_strings, pattern, limit)
    if not matches:
        return f"No strings matching '{pattern}'."
    n = len(matches)
    return _apply_aliases(f"Found {n} matches for '{pattern}':\n" + "\n".join(matches))


async def tool_find_string_refs(string: str, dex_index: int | None = None) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    results = await _call_analyzer(analyzer.find_string_refs, string, dex_index)
    if not results:
        return f"No methods reference {string!r}."
    return _apply_aliases(_join(results, f"Methods referencing {string!r}", 30))


async def tool_get_class_info(class_name: str) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    s = await _call_analyzer(analyzer.get_class_summary, class_name)
    if s is None:
        return f"Class '{class_name}' not found."

    lines = [
        f"=== {s.name} ===",
        f"Super: {s.superclass}  Access: {s.access}",
    ]
    if s.interfaces:
        lines.append(f"Interfaces: {', '.join(s.interfaces)}")

    # Fields
    lines.append(f"\nFields ({s.total_fields} total{', showing ' + str(len(s.fields)) if s.total_fields > MAX_FIELD_DISPLAY else ''}):")
    for f in s.fields:
        iv = f" = {f.init_value}" if f.init_value else ""
        lines.append(f"  {f.access} {f.type} {f.name}{iv}")

    # Methods
    shown = len(s.methods)
    lines.append(f"\nMethods ({s.total_methods} total{', showing ' + str(shown) if s.total_methods > MAX_METHOD_DISPLAY else ''}):")
    for m in s.methods:
        marker = "…" if m.instr_count > MAX_BYTECODE_INSTRS else ""
        lines.append(f"  {m.access} {m.name}{m.descriptor} ({m.instr_count}{marker} instrs)")

    # Xref
    if s.xref_from:
        lines.append(f"\nReferenced by ({len(s.xref_from)} shown{', more exist' if len(s.xref_from) >= MAX_XREF_DISPLAY else ''}):")
        for ref in s.xref_from:
            lines.append(f"  {ref}")

    return _apply_aliases("\n".join(lines))


async def tool_get_bytecode(
    class_name: str,
    method_name: str,
    method_desc: str = "",
    offset: int = 0,
    limit: int = MAX_BYTECODE_INSTRS,
) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    limit = min(limit, MAX_BYTECODE_INSTRS)
    data = await _call_analyzer(analyzer.get_bytecode, class_name, method_name, method_desc, offset, limit)
    if data is None:
        return f"Method '{method_name}' not found in class '{class_name}'."

    lines = [
        f"=== {data['signature']} === [{data['access']}]",
        f"Offset {data['offset']}, showing {len(data['instructions'])} instructions",
    ]
    if data.get("note"):
        lines.append(f"Note: {data['note']}")

    for instr in data["instructions"]:
        lines.append(f"  [{instr.idx:4d}] {instr.op:30s} {instr.show or ''}")

    if data.get("has_more"):
        next_offset = data["offset"] + len(data["instructions"])
        lines.append(f"\n... use offset={next_offset} for next page")

    return _apply_aliases("\n".join(lines))


async def tool_get_xref(method_signature: str, direction: str = "both") -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    data = await _call_analyzer(analyzer.get_xref, method_signature)
    if data is None:
        return f"Method not found or invalid signature: {method_signature}"

    lines = [f"=== XREF {data.signature} ==="]
    if direction in ("from", "both"):
        lines.append(f"\nCallers ({data.total_callers} total, showing {len(data.callers)}):")
        for c in data.callers:
            lines.append(f"  {c}")
        if data.total_callers > len(data.callers):
            lines.append(f"  ... {data.total_callers - len(data.callers)} more")

    if direction in ("to", "both"):
        lines.append(f"\nCallees ({data.total_callees} total, showing {len(data.callees)}):")
        for c in data.callees:
            lines.append(f"  {c}")
        if data.total_callees > len(data.callees):
            lines.append(f"  ... {data.total_callees - len(data.callees)} more")

    return _apply_aliases("\n".join(lines))


async def tool_get_static_fields(class_name: str) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    fields = await _call_analyzer(analyzer.get_static_fields, class_name)
    if fields is None:
        return f"Class '{class_name}' not found."
    if not fields:
        return f"=== Static fields of {class_name} ===\n  (none)"

    lines = [f"=== Static fields of {class_name} ({len(fields)} shown) ==="]
    for f in fields:
        val = ""
        if f.init_hex:
            val = f" = {f.init_hex}"
        elif f.init_label:
            val = f" = {f.init_label}"
        lines.append(f"  {f.type} {f.name}{val}")
    return _apply_aliases("\n".join(lines))


async def tool_search_class(pattern: str, limit: int = MAX_CLASS_RESULTS) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    limit = min(limit, MAX_CLASS_RESULTS)
    matches = await _call_analyzer(analyzer.search_classes, pattern, limit)
    if not matches:
        return f"No classes matching '{pattern}'."
    n = len(matches)
    return _apply_aliases(f"Classes matching '{pattern}' ({n}):\n" + "\n".join(f"  {m}" for m in matches))


async def tool_get_manifest() -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    m = await _call_analyzer(analyzer.get_manifest_summary)
    if m is None:
        return "Error: No APK loaded."

    lines = [
        f"=== {m.app_name} ({m.package}) ===",
        f"Version: {m.version_name} (code {m.version_code})",
        f"SDK: min={m.min_sdk} target={m.target_sdk}",
        f"\nPermissions ({m.total_permissions} total, showing {len(m.permissions)}):",
    ]
    for p in m.permissions:
        lines.append(f"  - {p}")
    if m.total_permissions > len(m.permissions):
        lines.append(f"  ... {m.total_permissions - len(m.permissions)} more")

    lines.append(f"\nActivities ({m.total_activities} total, showing {len(m.activities)}):")
    for a in m.activities:
        lines.append(f"  - {a}")
    if m.total_activities > len(m.activities):
        lines.append(f"  ... {m.total_activities - len(m.activities)} more")

    lines.append(f"\nServices ({len(m.services)}):")
    for s in m.services:
        lines.append(f"  - {s}")
    lines.append(f"\nReceivers ({len(m.receivers)}):")
    for r in m.receivers:
        lines.append(f"  - {r}")

    return _apply_aliases("\n".join(lines))


async def tool_get_method_info(class_name: str, method_name: str, method_desc: str = "") -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    info = await _call_analyzer(analyzer.get_method_info, class_name, method_name, method_desc)
    if info is None:
        return f"Method '{method_name}' not found in class '{class_name}'."

    lines = [
        f"=== {info.signature} ===",
        f"Access: {info.access}  Instructions: {info.instr_count}",
        f"\nCallers ({info.total_callers} total, showing {len(info.callers)}):",
    ]
    for c in info.callers:
        lines.append(f"  {c}")
    if info.total_callers > len(info.callers):
        lines.append(f"  ... {info.total_callers - len(info.callers)} more")

    lines.append("\nTop callee classes:")
    for cn, count in info.top_callee_classes.items():
        lines.append(f"  {cn}: {count} calls")

    return _apply_aliases("\n".join(lines))


# ---------------------------------------------------------------------------
# DB tool implementations
# ---------------------------------------------------------------------------

async def tool_load_db(path: str | None = None, create_if_missing: bool = False) -> str:
    if db.loaded:
        return "Error: DB already loaded."
    if path is None:
        if not analyzer.loaded:
            return "Error: APK not loaded; load_apk first or specify path explicitly."
        path = analyzer.path + ".sqlite"
    try:
        await _call_analyzer(db.open, path, create_if_missing)
    except FileNotFoundError as e:
        return f"Error: {e}. Use create_if_missing=true to create a new DB."
    count = await _call_analyzer(db.alias_count)
    return f"Loaded DB: {path} ({count} aliases)"


async def tool_set_alias(original: str, alias: str, note: str = "") -> str:
    if not db.loaded:
        return "Error: No DB loaded."
    await _call_analyzer(db.set_alias, original, alias, note)
    result = f"Alias set: [{alias}] {original}"
    if note:
        result += f"\n  Note: {note}"
    return result


async def tool_get_alias(original: str) -> str:
    if not db.loaded:
        return "Error: No DB loaded."
    result = await _call_analyzer(db.get_alias, original)
    if result is None:
        return f"No alias for: {original}"
    alias, note = result
    out = f"[{alias}] {original}"
    if note:
        out += f"\n  Note: {note}"
    return out


async def tool_list_aliases(pattern: str = "") -> str:
    if not db.loaded:
        return "Error: No DB loaded."
    rows = await _call_analyzer(db.list_aliases, pattern)
    if not rows:
        return "No aliases found." if not pattern else f"No aliases matching '{pattern}'."
    shown = rows[:MAX_ALIAS_LIST]
    lines = [f"Aliases ({len(rows)} total{', showing ' + str(len(shown)) if len(rows) > MAX_ALIAS_LIST else ''}):"]
    for r in shown:
        note_str = f"  # {r['note']}" if r["note"] else ""
        lines.append(f"  [{r['alias']}] {r['original']}{note_str}")
    return "\n".join(lines)


async def tool_delete_alias(original: str) -> str:
    if not db.loaded:
        return "Error: No DB loaded."
    found = await _call_analyzer(db.delete_alias, original)
    if found:
        return f"Deleted alias for: {original}"
    return f"No alias found for: {original}"


# ---------------------------------------------------------------------------
# MCP Server setup
# ---------------------------------------------------------------------------
TOOL_MAP: dict[str, Any] = {
    "list_apks": tool_list_apks,
    "load_apk": tool_load_apk,
    "load_db": tool_load_db,
    "search_string": tool_search_string,
    "find_string_refs": tool_find_string_refs,
    "get_class_info": tool_get_class_info,
    "get_bytecode": tool_get_bytecode,
    "get_xref": tool_get_xref,
    "get_static_fields": tool_get_static_fields,
    "search_class": tool_search_class,
    "get_manifest": tool_get_manifest,
    "get_method_info": tool_get_method_info,
    "set_alias": tool_set_alias,
    "get_alias": tool_get_alias,
    "list_aliases": tool_list_aliases,
    "delete_alias": tool_delete_alias,
}

app = Server("androguard-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOL_DEFINITIONS


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        func = TOOL_MAP.get(name)
        if func is None:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        result = await func(**arguments)
        return [TextContent(type="text", text=str(result))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {type(e).__name__}: {e}")]


PORT = int(os.environ.get("ANDROGUARD_MCP_PORT", "18765"))


def create_starlette_app() -> Starlette:
    session_manager = StreamableHTTPSessionManager(app=app, stateless=False)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async with session_manager.run():
            yield

    return Starlette(
        routes=[Mount("/sse", app=session_manager.handle_request)],
        lifespan=lifespan,
    )


def cli() -> None:
    import uvicorn
    uvicorn.run(create_starlette_app(), host="127.0.0.1", port=PORT)


if __name__ == "__main__":
    cli()
