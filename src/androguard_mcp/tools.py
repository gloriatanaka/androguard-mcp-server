"""MCP tool definitions and their schemas."""

from mcp.types import Tool

TOOL_DEFINITIONS = [
    Tool(
        name="list_apks",
        description="List all .apk files in the current workspace directory",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="load_apk",
        description="Load an APK file for analysis. Must be called before any analysis tools. The file path is relative to the workspace.",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the .apk file",
                }
            },
            "required": ["path"],
        },
    ),
    Tool(
        name="search_string",
        description="Search for strings in the APK's DEX string pools using a regex pattern (case-insensitive).",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (case-insensitive)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default 50)",
                },
            },
            "required": ["pattern"],
        },
    ),
    Tool(
        name="find_string_refs",
        description="Find all methods that reference a specific exact string via const-string instruction.",
        inputSchema={
            "type": "object",
            "properties": {
                "string": {
                    "type": "string",
                    "description": "Exact string to search for",
                },
                "dex_index": {
                    "type": "integer",
                    "description": "Optional: limit search to a specific DEX file index",
                },
            },
            "required": ["string"],
        },
    ),
    Tool(
        name="get_class_info",
        description="Get full summary of a class: superclass, interfaces, fields (with initial values), methods (with code sizes), and external references.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {
                    "type": "string",
                    "description": "Full class name, e.g. 'LX/1Af;' or 'Ljava/lang/String;'",
                },
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="get_bytecode",
        description="Get Dalvik bytecode for a method. Paginated — use offset for subsequent pages. Max 60 instructions per page.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
                "method_name": {
                    "type": "string",
                    "description": "Method name, e.g. '<init>' or 'A05'",
                },
                "method_desc": {
                    "type": "string",
                    "description": "Optional: method descriptor to disambiguate overloaded methods",
                },
                "offset": {
                    "type": "integer",
                    "description": "Instruction offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max instructions to return (default 60, max 60)",
                },
            },
            "required": ["class_name", "method_name"],
        },
    ),
    Tool(
        name="get_xref",
        description="Get cross-references for a method: who calls it ('from') and what it calls ('to').",
        inputSchema={
            "type": "object",
            "properties": {
                "method_signature": {
                    "type": "string",
                    "description": "Method signature in format 'Lclass;->methodName(Lparam;)V'",
                },
                "direction": {
                    "type": "string",
                    "enum": ["from", "to", "both"],
                    "description": "Direction: 'from' (callers), 'to' (callees), or 'both' (default)",
                },
            },
            "required": ["method_signature"],
        },
    ),
    Tool(
        name="get_static_fields",
        description="Get static fields and their initial values for a class.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="search_class",
        description="Search for classes whose names match a regex pattern.",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to match against class names (case-insensitive)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default 50)",
                },
            },
            "required": ["pattern"],
        },
    ),
    Tool(
        name="get_manifest",
        description="Get the AndroidManifest summary: package, version, permissions, activities, services, receivers.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="get_method_info",
        description="Get a method's signature, access flags, code size, and cross-reference summary.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
                "method_name": {"type": "string", "description": "Method name"},
                "method_desc": {
                    "type": "string",
                    "description": "Optional: method descriptor to disambiguate overloaded methods",
                },
            },
            "required": ["class_name", "method_name"],
        },
    ),
]
