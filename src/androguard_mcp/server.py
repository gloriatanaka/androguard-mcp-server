"""androguard MCP Server — strict bounded-output tool implementations."""

import os
from typing import Any

# Suppress androguard loguru noise
from loguru import logger

logger.remove()

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

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
from androguard_mcp.tools import TOOL_DEFINITIONS

WORKSPACE_DIR = os.getcwd()

# ---- output formatters ----
# Keep each tool's text output under ~2000 chars / ~60 lines.
# Structured repeating lines (list items) are the main consumer;
# we limit those per tool.


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
    info = analyzer.load(apk_path)
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
    matches = analyzer.search_strings(pattern, limit)
    if not matches:
        return f"No strings matching '{pattern}'."
    n = len(matches)
    return f"Found {n} matches for '{pattern}':\n" + "\n".join(matches)


async def tool_find_string_refs(string: str, dex_index: int | None = None) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    results = analyzer.find_string_refs(string, dex_index)
    if not results:
        return f"No methods reference {string!r}."
    return _join(results, f"Methods referencing {string!r}", 30)


async def tool_get_class_info(class_name: str) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    s = analyzer.get_class_summary(class_name)
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

    return "\n".join(lines)


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
    data = analyzer.get_bytecode(class_name, method_name, method_desc, offset, limit)
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

    return "\n".join(lines)


async def tool_get_xref(method_signature: str, direction: str = "both") -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    data = analyzer.get_xref(method_signature)
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

    return "\n".join(lines)


async def tool_get_static_fields(class_name: str) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    fields = analyzer.get_static_fields(class_name)
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
    return "\n".join(lines)


async def tool_search_class(pattern: str, limit: int = MAX_CLASS_RESULTS) -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    limit = min(limit, MAX_CLASS_RESULTS)
    matches = analyzer.search_classes(pattern, limit)
    if not matches:
        return f"No classes matching '{pattern}'."
    n = len(matches)
    return f"Classes matching '{pattern}' ({n}):\n" + "\n".join(f"  {m}" for m in matches)


async def tool_get_manifest() -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    m = analyzer.get_manifest_summary()
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

    return "\n".join(lines)


async def tool_get_method_info(class_name: str, method_name: str, method_desc: str = "") -> str:
    if not analyzer.loaded:
        return "Error: No APK loaded."
    info = analyzer.get_method_info(class_name, method_name, method_desc)
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

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP Server setup
# ---------------------------------------------------------------------------
TOOL_MAP: dict[str, Any] = {
    "list_apks": tool_list_apks,
    "load_apk": tool_load_apk,
    "search_string": tool_search_string,
    "find_string_refs": tool_find_string_refs,
    "get_class_info": tool_get_class_info,
    "get_bytecode": tool_get_bytecode,
    "get_xref": tool_get_xref,
    "get_static_fields": tool_get_static_fields,
    "search_class": tool_search_class,
    "get_manifest": tool_get_manifest,
    "get_method_info": tool_get_method_info,
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


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def cli() -> None:
    import asyncio
    asyncio.run(main())


if __name__ == "__main__":
    cli()
