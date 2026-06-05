# androguard-mcp-server

MCP (Model Context Protocol) server wrapping [androguard](https://github.com/androguard/androguard) for AI-assisted APK reverse engineering.

Provides structured, indexed access to APK internals at the **DEX bytecode level** — no decompilation artifacts, no smali parsing, just direct DEX analysis.

## Tools

### Session Setup

| Tool | Description |
|---|---|
| `list_apks` | List .apk files in the workspace |
| `load_apk` | Load an APK (cached in memory for subsequent calls) |
| `load_db` | Load (or create) the per-APK analysis database |

### Discovery

| Tool | Description |
|---|---|
| `get_manifest` | AndroidManifest summary: package, permissions, activities, services |
| `search_class` | Regex search for class names |
| `search_string` | Regex search across all DEX string pools |
| `find_string_refs` | Find methods referencing a specific string (`const-string`) — paginated |
| `search_method` | Regex search for method names across all classes — paginated |

### Code Inspection

| Tool | Description |
|---|---|
| `get_class_info` | Class summary: superclass, interfaces, fields, methods |
| `list_fields` | All fields of a class with types and initial values — paginated |
| `list_methods` | All methods of a class with descriptors and code sizes — paginated |
| `get_method_info` | Method summary with cross-reference overview |
| `get_bytecode` | Dalvik bytecode for a method (paginated, 60 instrs/page) |
| `get_xref` | Method cross-references: callers and callees — paginated |
| `get_field_xref` | Field cross-references: which methods read or write a field — paginated |
| `get_static_fields` | Static fields with initial values (string tables, constants) |

### Alias / Naming

| Tool | Description |
|---|---|
| `set_alias` | Assign a semantic name to an obfuscated class, method, or field |
| `get_alias` | Look up the alias for a specific name |
| `list_aliases` | List aliases, optionally filtered by substring — paginated |
| `delete_alias` | Remove an alias |

Once a DB is loaded, aliases appear inline in all analysis tool outputs as `[alias] original`, so both the human-readable name and the machine-readable original are visible.

#### Typical workflow

```
load_apk("app.apk")
load_db(create_if_missing=true)         # creates app.apk.sqlite next to the APK
set_alias("Lcom/a/b/c;", "AuthManager", note="handles JWT validation")
get_class_info("Lcom/a/b/c;")          # output now shows [AuthManager] Lcom/a/b/c;
```

The DB persists across server restarts — reload with `load_apk` + `load_db` to restore all aliases.

## Transport: HTTP (Streamable HTTP)

The server runs as an HTTP server using the MCP Streamable HTTP transport. This avoids the stdio pollution issue that arises when androguard or its dependencies call `print()` internally.

### Starting the server

```bash
# Run from your APK workspace directory
androguard-mcp

# Or specify the workspace explicitly
ANDROGUARD_WORKSPACE=/path/to/apk/dir androguard-mcp

# Custom port (default: 18765)
ANDROGUARD_MCP_PORT=9000 androguard-mcp
```

The server listens on `http://127.0.0.1:18765` by default.

### Configuring Claude Code

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "androguard": {
      "type": "http",
      "url": "http://127.0.0.1:18765/sse"
    }
  }
}
```

> **Note:** The server must be started manually before Claude Code connects to it. It does not auto-start like stdio-mode servers.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ANDROGUARD_MCP_PORT` | `18765` | TCP port to listen on |
| `ANDROGUARD_WORKSPACE` | `$PWD` | Directory scanned for APKs and used as the base path for `load_apk` |

## Notes on method names

Dalvik constructor and static-initializer methods (`<init>`, `<clinit>`) can be passed with or without angle brackets — the server normalises HTML-entity-encoded names (`&lt;init&gt;` → `<init>`) automatically.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

## License

MIT
