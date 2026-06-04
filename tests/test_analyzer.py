"""Unit/integration tests for APKAnalyzer (no MCP transport)."""

import os
import re

import pytest

from androguard_mcp import APKAnalyzer, _is_const_string, MAX_PERMISSIONS, MAX_ACTIVITIES
from conftest import APK_PATH, requires_apk


class TestAPKAnalyzerNoAPK:
    """Tests that don't need a real APK loaded."""

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


class TestAPKAnalyzerLoad:
    @requires_apk
    def test_load_succeeds(self, loaded_analyzer):
        assert loaded_analyzer.loaded
        info = loaded_analyzer.get_manifest_summary()
        assert info is not None
        assert info.package == "com.google.android.deskclock"

    @requires_apk
    def test_find_dex_for_class(self, loaded_analyzer):
        result = loaded_analyzer.find_dex_for_class("Laej;")
        assert result is not None
        dx, dex_idx = result
        assert dex_idx == 0
        assert dx.get_class("Laej;") is not None

    @requires_apk
    def test_find_dex_for_missing_class(self, loaded_analyzer):
        assert loaded_analyzer.find_dex_for_class("Lcom/nonexistent/Class;") is None


class TestAPKAnalyzerStrings:
    @requires_apk
    def test_search_string_exact(self, loaded_analyzer):
        matches = loaded_analyzer.search_strings("^TypefaceCompat static init$")
        assert len(matches) >= 1
        assert "TypefaceCompat static init" in matches[0]

    @requires_apk
    def test_search_string_pattern(self, loaded_analyzer):
        matches = loaded_analyzer.search_strings("alarm", limit=10)
        assert len(matches) >= 1
        for m in matches:
            assert "alarm" in m.lower()

    @requires_apk
    def test_search_string_no_match(self, loaded_analyzer):
        matches = loaded_analyzer.search_strings("ZZZZNOTEXISTSZZZZ")
        assert matches == []

    @requires_apk
    def test_search_string_limit(self, loaded_analyzer):
        matches = loaded_analyzer.search_strings(".", limit=5)
        assert len(matches) == 5

    @requires_apk
    def test_find_string_refs_noise(self, loaded_analyzer):
        results = loaded_analyzer.find_string_refs("KeyAttribute")
        assert len(results) > 0
        assert any("Laau;" in r for r in results)

    @requires_apk
    def test_find_string_refs_missing(self, loaded_analyzer):
        results = loaded_analyzer.find_string_refs("ZZZZNOTEXISTSZZZZ")
        assert results == []


class TestAPKAnalyzerClasses:
    @requires_apk
    def test_search_class_exact(self, loaded_analyzer):
        matches = loaded_analyzer.search_classes("^Laej;$")
        assert len(matches) >= 1
        assert any("Laej;" in m for m in matches)

    @requires_apk
    def test_search_class_pattern(self, loaded_analyzer):
        matches = loaded_analyzer.search_classes("Laej")
        assert len(matches) > 0

    @requires_apk
    def test_search_class_limit(self, loaded_analyzer):
        matches = loaded_analyzer.search_classes("La", limit=10)
        assert len(matches) == 10

    @requires_apk
    def test_get_class_summary(self, loaded_analyzer):
        summary = loaded_analyzer.get_class_summary("Laej;")
        assert summary is not None
        assert summary.name == "Laej;"
        assert summary.superclass == "Laeq;"
        assert len(summary.fields) >= 5
        assert len(summary.methods) > 0

    @requires_apk
    def test_get_class_summary_missing(self, loaded_analyzer):
        assert loaded_analyzer.get_class_summary("Lcom/nonexistent/Class;") is None


class TestAPKAnalyzerStaticFields:
    @requires_apk
    def test_get_static_fields_noise_table(self, loaded_analyzer):
        fields = loaded_analyzer.get_static_fields("Laej;")
        assert fields is not None
        assert len(fields) >= 5
        field_names = {f.name for f in fields}
        for expected in ["a", "b", "c", "d", "e"]:
            assert expected in field_names

    @requires_apk
    def test_get_static_fields_missing(self, loaded_analyzer):
        assert loaded_analyzer.get_static_fields("Lcom/nonexistent/Class;") is None


class TestAPKAnalyzerBytecode:
    @requires_apk
    def test_get_bytecode_clinit(self, loaded_analyzer):
        bc = loaded_analyzer.get_bytecode("Laau;", "<clinit>")
        assert bc is not None
        instrs = bc["instructions"]
        assert len(instrs) > 0
        ops = {instr.op for instr in instrs}
        assert "const-string" in ops

    @requires_apk
    def test_get_bytecode_missing_class(self, loaded_analyzer):
        assert loaded_analyzer.get_bytecode("Lfoo;", "bar") is None

    @requires_apk
    def test_get_bytecode_missing_method(self, loaded_analyzer):
        assert loaded_analyzer.get_bytecode("Laej;", "nonexistent_method") is None

    @requires_apk
    def test_get_bytecode_pagination(self, loaded_analyzer):
        page0 = loaded_analyzer.get_bytecode("Laau;", "<clinit>", offset=0, limit=5)
        page1 = loaded_analyzer.get_bytecode("Laau;", "<clinit>", offset=5, limit=5)
        assert page0 is not None and page1 is not None
        assert page0["instructions"] != page1["instructions"]


class TestAPKAnalyzerXref:
    @requires_apk
    def test_get_xref_constructor(self, loaded_analyzer):
        data = loaded_analyzer.get_xref("Laej;-><clinit>()V")
        assert data is not None
        assert hasattr(data, "callers")
        assert hasattr(data, "callees")

    @requires_apk
    def test_get_xref_invalid(self, loaded_analyzer):
        assert loaded_analyzer.get_xref("garbage") is None

    @requires_apk
    def test_get_xref_missing(self, loaded_analyzer):
        assert loaded_analyzer.get_xref("Lcom/Foo;->bar()V") is None


class TestAPKAnalyzerMethodInfo:
    @requires_apk
    def test_get_method_info_clinit(self, loaded_analyzer):
        info = loaded_analyzer.get_method_info("Laej;", "<clinit>")
        assert info is not None
        assert "Laej;" in info.signature
        assert info.instr_count > 0

    @requires_apk
    def test_get_method_info_with_desc(self, loaded_analyzer):
        info = loaded_analyzer.get_method_info("Laej;", "<init>", "()V")
        assert info is not None
        assert info.instr_count > 0
        assert hasattr(info, "callers")

    @requires_apk
    def test_get_method_info_missing(self, loaded_analyzer):
        assert loaded_analyzer.get_method_info("Lfoo;", "bar") is None


class TestAPKAnalyzerManifest:
    @requires_apk
    def test_get_manifest(self, loaded_analyzer):
        m = loaded_analyzer.get_manifest_summary()
        assert m is not None
        assert m.package == "com.google.android.deskclock"
        # Verify actual APK counts (total, not the truncated display list)
        assert m.total_permissions > 5
        assert m.total_activities > 10
        assert m.total_services > 5
        assert m.total_receivers > 5
        # Verify display lists are bounded
        assert len(m.permissions) <= MAX_PERMISSIONS
        assert len(m.activities) <= MAX_ACTIVITIES
        assert len(m.services) <= MAX_ACTIVITIES
        assert len(m.receivers) <= MAX_ACTIVITIES

    @requires_apk
    def test_manifest_no_apk(self):
        a = APKAnalyzer()
        assert a.get_manifest_summary() is None
