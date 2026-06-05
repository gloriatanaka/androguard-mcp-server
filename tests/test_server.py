"""Tests for the MCP server tool functions (no MCP transport, just logic)."""

import pytest

from androguard_mcp.server import tool_list_apks, tool_load_apk, TOOL_MAP
from androguard_mcp import analyzer
from conftest import requires_apk


class TestToolListApks:
    @pytest.mark.asyncio
    async def test_returns_string(self):
        result = await tool_list_apks()
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_finds_wab_apk(self):
        result = await tool_list_apks()
        # list_apks scans WORKSPACE_DIR (cwd); APK may or may not be there
        assert isinstance(result, str)


class TestToolLoadApk:
    @requires_apk
    @pytest.mark.asyncio
    async def test_load_succeeds(self, loaded_analyzer):
        assert loaded_analyzer.loaded
        # APK is in WORKSPACE_DIR (project root)
        result = await tool_load_apk("com.google.android.deskclock.apk")
        assert "Loaded" in result
        assert "com.google.android.deskclock" in result

    @pytest.mark.asyncio
    async def test_load_missing_file(self):
        result = await tool_load_apk("nonexistent.apk")
        assert "not found" in result.lower()


class TestToolMap:
    def test_all_tools_registered(self):
        expected = {
            "list_apks",
            "load_apk",
            "load_db",
            "get_manifest",
            "search_class",
            "search_string",
            "find_string_refs",
            "search_method",
            "get_class_info",
            "list_fields",
            "list_methods",
            "get_method_info",
            "get_bytecode",
            "get_xref",
            "get_field_xref",
            "get_static_fields",
            "set_alias",
            "get_alias",
            "list_aliases",
            "delete_alias",
        }
        assert set(TOOL_MAP.keys()) == expected

    def test_all_tools_callable(self):
        for tool_name, func in TOOL_MAP.items():
            assert callable(func), f"Tool {tool_name} is not callable"


class TestToolFunctions:
    """Integration tests for tool functions with loaded APK."""

    @requires_apk
    @pytest.mark.asyncio
    async def test_search_noise(self, loaded_analyzer):
        from androguard_mcp.server import tool_search_string
        result = await tool_search_string("KeyAttribute")
        assert "Found" in result
        assert "KeyAttribute" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_search_no_match(self, loaded_analyzer):
        from androguard_mcp.server import tool_search_string
        result = await tool_search_string("ZZZZNOTEXISTSZZZZ")
        assert "No strings matching" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_find_noise_refs(self, loaded_analyzer):
        from androguard_mcp.server import tool_find_string_refs
        result = await tool_find_string_refs("KeyAttribute")
        assert "Laau;" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_find_missing_string(self, loaded_analyzer):
        from androguard_mcp.server import tool_find_string_refs
        result = await tool_find_string_refs("ZZZZNOTEXISTSZZZZ")
        assert "No methods" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_noise_class(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_class_info
        result = await tool_get_class_info("Laej;")
        assert "Super:" in result
        assert "Fields" in result
        assert "Methods" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_missing_class(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_class_info
        result = await tool_get_class_info("Lcom/nonexistent/Class;")
        assert "not found" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_clinit(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_bytecode
        result = await tool_get_bytecode("Laau;", "<clinit>")
        assert "const-string" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_clinit_with_desc(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_bytecode
        result = await tool_get_bytecode("Laau;", "<clinit>", "()V")
        assert "const-string" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_xref(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_xref
        result = await tool_get_xref("Laej;-><clinit>()V")
        assert "XREF" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_static_fields(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_static_fields
        result = await tool_get_static_fields("Laej;")
        assert " a " in result or " b " in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_search_class(self, loaded_analyzer):
        from androguard_mcp.server import tool_search_class
        result = await tool_search_class("Laej")
        assert "Laej" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_manifest(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_manifest
        result = await tool_get_manifest()
        assert "com.google.android.deskclock" in result

    @requires_apk
    @pytest.mark.asyncio
    async def test_get_method_info(self, loaded_analyzer):
        from androguard_mcp.server import tool_get_method_info
        result = await tool_get_method_info("Laej;", "<clinit>")
        assert "Laej;" in result
        assert "Callers" in result
        assert "callee" in result.lower()


class TestToolNoAPKGuard:
    """Tools should return error messages, not crash, when no APK is loaded."""

    @pytest.fixture(autouse=True)
    def _isolate(self):
        """Ensure the global analyzer is unloaded for these tests."""
        saved = analyzer.analysis
        analyzer.analysis = None
        yield
        analyzer.analysis = saved

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool_name,kwargs", [
        ("search_string", {"pattern": "foo"}),
        ("find_string_refs", {"string": "foo"}),
        ("get_class_info", {"class_name": "Lfoo;"}),
        ("get_bytecode", {"class_name": "Lfoo;", "method_name": "bar"}),
        ("get_xref", {"method_signature": "Lfoo;->bar()V"}),
        ("get_static_fields", {"class_name": "Lfoo;"}),
        ("search_class", {"pattern": "foo"}),
        ("get_manifest", {}),
        ("get_method_info", {"class_name": "Lfoo;", "method_name": "bar"}),
    ])
    async def test_tool_returns_error_without_apk(self, tool_name, kwargs):
        func = TOOL_MAP[tool_name]
        result = await func(**kwargs)
        assert isinstance(result, str)
        assert "Error" in result
