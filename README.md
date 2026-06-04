# androguard-mcp-server

MCP (Model Context Protocol) server wrapping [androguard](https://github.com/androguard/androguard) for AI-assisted APK reverse engineering.

Provides structured, indexed access to APK internals at the **DEX bytecode level** — no decompilation artifacts, no smali parsing, just direct DEX analysis.

## Tools

| Tool | Description |
|---|---|
| `list_apks` | List .apk files in the workspace |
| `load_apk` | Load an APK (cached in memory for subsequent calls) |
| `search_string` | Regex search across all DEX string pools |
| `find_string_refs` | Find methods referencing a specific string (`const-string`) |
| `get_class_info` | Class summary: superclass, interfaces, fields, methods |
| `get_static_fields` | Static fields with initial values (string tables, constants) |
| `get_bytecode` | Full Dalvik bytecode for a method |
| `get_method_info` | Method summary with cross-reference overview |
| `get_xref` | Cross-references: callers and callees |
| `search_class` | Regex search for class names |
| `get_manifest` | AndroidManifest summary |

## Usage with Claude Code

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "androguard": {
      "command": "/path/to/venv/bin/python3",
      "args": ["-m", "androguard_mcp.server"],
      "env": {}
    }
  }
}
```

Or install the package first, then use the entry point:

```json
{
  "mcpServers": {
    "androguard": {
      "command": "/path/to/venv/bin/androguard-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

## Development

```
pip install -e ".[dev]"
pytest -v
```

## License

MIT
