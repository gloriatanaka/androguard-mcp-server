"""Pure unit tests that don't need an APK."""

import pytest

from androguard_mcp import APKAnalyzer, _is_const_string
from androguard_mcp.server import TOOL_MAP


class TestAPKAnalyzerNoAPK:
    def test_initial_state(self):
        a = APKAnalyzer()
        assert not a.loaded
        assert a.apk is None
        assert a.dex_list == []
        assert a.find_dex_for_class("LX/1Af;") is None
        assert a.search_strings(".*") == []
        assert a.search_classes(".*") == []
        assert a.find_string_refs("test") == []
        assert a.get_bytecode("Lfoo;", "bar") is None
        assert a.get_xref("Lfoo;->bar()V") is None
        assert a.get_class_summary("Lfoo;") is None
        assert a.get_static_fields("Lfoo;") is None
        assert a.get_method_info("Lfoo;", "bar") is None
        assert a.get_manifest_summary() is None

    def test_is_const_string(self):
        class MockInstr:
            def get_name(self):
                return "const-string"
        assert _is_const_string(MockInstr())

        class MockInstr2:
            def get_name(self):
                return "const-string/jumbo"
        assert _is_const_string(MockInstr2())

        class MockInstr3:
            def get_name(self):
                return "invoke-virtual"
        assert not _is_const_string(MockInstr3())


class TestServerNoAPK:
    @pytest.fixture(autouse=True)
    def _isolate(self):
        """Ensure the global analyzer is unloaded for these tests."""
        from androguard_mcp import analyzer
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

    def test_all_tools_registered(self):
        expected = {
            "list_apks",
            "load_apk",
            "load_db",
            "search_string",
            "find_string_refs",
            "get_class_info",
            "get_bytecode",
            "get_xref",
            "get_static_fields",
            "search_class",
            "get_manifest",
            "get_method_info",
            "set_alias",
            "get_alias",
            "list_aliases",
            "delete_alias",
        }
        assert set(TOOL_MAP.keys()) == expected

    def test_all_tools_callable(self):
        for tool_name, func in TOOL_MAP.items():
            assert callable(func), f"Tool {tool_name} is not callable"


class TestToolListApks:
    @pytest.mark.asyncio
    async def test_returns_apks(self):
        from androguard_mcp.server import tool_list_apks
        result = await tool_list_apks()
        assert isinstance(result, str)
        assert "APK files" in result or "No .apk" in result
