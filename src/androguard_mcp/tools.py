"""MCP tool definitions and their schemas."""

from mcp.types import Tool

TOOL_DEFINITIONS = [
    # ---- Session setup ----
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
        name="load_db",
        description=(
            "Load the per-APK analysis database (SQLite). "
            "Without a path, defaults to <apk_path>.sqlite — requires load_apk first. "
            "Set create_if_missing=true to create a new DB if it doesn't exist."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the .sqlite DB file. Omit to use <apk_path>.sqlite.",
                },
                "create_if_missing": {
                    "type": "boolean",
                    "description": "Create the DB file if it doesn't exist (default false)",
                },
            },
        },
    ),
    # ---- Discovery ----
    Tool(
        name="get_manifest",
        description="Get the AndroidManifest summary: package, version, permissions, activities, services, receivers.",
        inputSchema={"type": "object", "properties": {}},
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
        description="Find all methods that reference a specific exact string via const-string instruction. Paginated — use offset for subsequent pages.",
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
                "offset": {
                    "type": "integer",
                    "description": "Result offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results per page (default 50)",
                },
            },
            "required": ["string"],
        },
    ),
    Tool(
        name="search_method",
        description="Search for methods whose names match a regex pattern, across all classes. Paginated — use offset for subsequent pages.",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to match against method names (case-insensitive)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results per page (default 50)",
                },
                "offset": {
                    "type": "integer",
                    "description": "Result offset for pagination (default 0)",
                },
            },
            "required": ["pattern"],
        },
    ),
    # ---- Code inspection ----
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
        name="list_fields",
        description="List all fields of a class with their types, access flags, and initial values. Paginated — use offset for subsequent pages.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
                "offset": {
                    "type": "integer",
                    "description": "Field offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max fields to return (default 30)",
                },
            },
            "required": ["class_name"],
        },
    ),
    Tool(
        name="list_methods",
        description="List all methods of a class with their descriptors, access flags, and code sizes. Paginated — use offset for subsequent pages.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {"type": "string", "description": "Full class name"},
                "offset": {
                    "type": "integer",
                    "description": "Method offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max methods to return (default 30)",
                },
            },
            "required": ["class_name"],
        },
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
        description="Get cross-references for a method: who calls it ('from') and what it calls ('to'). Paginated — use offset for subsequent pages.",
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
                "offset": {
                    "type": "integer",
                    "description": "Result offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per page (default 15)",
                },
            },
            "required": ["method_signature"],
        },
    ),
    Tool(
        name="get_field_xref",
        description="Get cross-references for a field: which methods read it and which methods write it. Paginated — use offset for subsequent pages.",
        inputSchema={
            "type": "object",
            "properties": {
                "class_name": {
                    "type": "string",
                    "description": "Full class name containing the field",
                },
                "field_name": {
                    "type": "string",
                    "description": "Field name",
                },
                "field_type": {
                    "type": "string",
                    "description": "Optional: field type descriptor (e.g. 'Ljava/lang/String;') to disambiguate",
                },
                "direction": {
                    "type": "string",
                    "enum": ["read", "write", "both"],
                    "description": "Direction: 'read' (readers), 'write' (writers), or 'both' (default)",
                },
                "offset": {
                    "type": "integer",
                    "description": "Result offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per page (default 15)",
                },
            },
            "required": ["class_name", "field_name"],
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
    # ---- Alias management ----
    Tool(
        name="set_alias",
        description=(
            "Assign a semantic alias to an obfuscated class, method, or field. "
            "The alias is persisted in the DB and shown in all subsequent tool outputs. "
            "Use the exact original name as it appears in tool output (e.g. 'Lcom/a/b/c;' or 'Lcom/a/b/c;->a()V')."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "original": {
                    "type": "string",
                    "description": "Original obfuscated name (class descriptor, method signature, or field name)",
                },
                "alias": {
                    "type": "string",
                    "description": "Semantic name to assign (e.g. 'UserAuthManager')",
                },
                "note": {
                    "type": "string",
                    "description": "Optional free-form annotation or rationale",
                },
            },
            "required": ["original", "alias"],
        },
    ),
    Tool(
        name="get_alias",
        description="Look up the alias assigned to a specific class, method, or field name.",
        inputSchema={
            "type": "object",
            "properties": {
                "original": {
                    "type": "string",
                    "description": "Original obfuscated name to look up",
                },
            },
            "required": ["original"],
        },
    ),
    Tool(
        name="list_aliases",
        description="List aliases in the DB, optionally filtered by a substring pattern. Paginated — use offset for subsequent pages.",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Optional substring to filter by (matches original or alias)",
                },
                "offset": {
                    "type": "integer",
                    "description": "Result offset for pagination (default 0)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results per page (default 100)",
                },
            },
        },
    ),
    Tool(
        name="delete_alias",
        description="Remove an alias from the DB.",
        inputSchema={
            "type": "object",
            "properties": {
                "original": {
                    "type": "string",
                    "description": "Original obfuscated name whose alias should be deleted",
                },
            },
            "required": ["original"],
        },
    ),
]
