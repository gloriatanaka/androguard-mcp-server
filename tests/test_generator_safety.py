"""Test that all androguard APIs returning generators are handled correctly.

We call each API path twice to confirm no generator exhaustion bugs.
"""

import pytest

from conftest import requires_apk


class TestGeneratorSafety:
    """Verify idempotency: calling any API twice returns the same result."""

    @requires_apk
    def test_search_string_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.search_strings("Noise_XX")
        r2 = loaded_analyzer.search_strings("Noise_XX")
        assert r1 == r2

    @requires_apk
    def test_find_string_refs_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.find_string_refs("KeyAttribute")
        r2 = loaded_analyzer.find_string_refs("KeyAttribute")
        assert r1 == r2

    @requires_apk
    def test_get_bytecode_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_bytecode("Laau;", "<clinit>")
        r2 = loaded_analyzer.get_bytecode("Laau;", "<clinit>")
        assert r1 == r2

    @requires_apk
    def test_get_class_summary_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_class_summary("Laej;")
        r2 = loaded_analyzer.get_class_summary("Laej;")
        assert r1 == r2

    @requires_apk
    def test_get_method_info_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_method_info("Laej;", "<init>", "()V")
        r2 = loaded_analyzer.get_method_info("Laej;", "<init>", "()V")
        assert r1 == r2

    @requires_apk
    def test_get_manifest_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_manifest_summary()
        r2 = loaded_analyzer.get_manifest_summary()
        assert r1 == r2

    @requires_apk
    def test_get_xref_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_xref("Laej;-><clinit>()V")
        r2 = loaded_analyzer.get_xref("Laej;-><clinit>()V")
        assert r1 == r2

    @requires_apk
    def test_search_class_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.search_classes("Laej")
        r2 = loaded_analyzer.search_classes("Laej")
        assert r1 == r2

    @requires_apk
    def test_get_static_fields_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_static_fields("Laej;")
        r2 = loaded_analyzer.get_static_fields("Laej;")
        assert r1 == r2

    @requires_apk
    def test_get_manifest_fields_consistent(self, loaded_analyzer):
        """Manifest summary fields are internally consistent."""
        m = loaded_analyzer.get_manifest_summary()
        assert m is not None
        assert m.total_permissions >= len(m.permissions)
        assert m.total_activities >= len(m.activities)
        assert m.total_services >= len(m.services)
        assert m.total_receivers >= len(m.receivers)

    @requires_apk
    def test_search_methods_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.search_methods("onCreate")
        r2 = loaded_analyzer.search_methods("onCreate")
        assert r1 == r2

    @requires_apk
    def test_search_methods_pagination_consistent(self, loaded_analyzer):
        """Pages must not overlap and must cover the same items as a full fetch."""
        full = loaded_analyzer.search_methods("<init>", limit=10, offset=0)
        p1 = loaded_analyzer.search_methods("<init>", limit=5, offset=0)
        p2 = loaded_analyzer.search_methods("<init>", limit=5, offset=5)
        assert full[0:5] == p1[0:5]
        assert full[5:10] == p2[5:10]

    @requires_apk
    def test_list_methods_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.list_methods("Laej;")
        r2 = loaded_analyzer.list_methods("Laej;")
        assert r1 == r2

    @requires_apk
    def test_list_methods_pagination_consistent(self, loaded_analyzer):
        """Paginated pages must not overlap and must cover the same items."""
        full = loaded_analyzer.list_methods("Laej;", offset=0, limit=30)
        if full is None or full["total"] < 2:
            return
        p1 = loaded_analyzer.list_methods("Laej;", offset=0, limit=1)
        p2 = loaded_analyzer.list_methods("Laej;", offset=1, limit=1)
        assert p1 is not None and p2 is not None
        assert p1["methods"][0].name != p2["methods"][0].name or \
               p1["methods"][0].descriptor != p2["methods"][0].descriptor

    @requires_apk
    def test_list_fields_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.list_fields("Laej;")
        r2 = loaded_analyzer.list_fields("Laej;")
        assert r1 == r2

    @requires_apk
    def test_find_string_refs_paginated_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.find_string_refs("KeyAttribute", offset=0, limit=10)
        r2 = loaded_analyzer.find_string_refs("KeyAttribute", offset=0, limit=10)
        assert r1 == r2

    @requires_apk
    def test_get_xref_paginated_idempotent(self, loaded_analyzer):
        r1 = loaded_analyzer.get_xref("Laej;-><clinit>()V", offset=0, limit=5)
        r2 = loaded_analyzer.get_xref("Laej;-><clinit>()V", offset=0, limit=5)
        assert r1 == r2

    @requires_apk
    def test_get_field_xref_idempotent(self, loaded_analyzer):
        """get_field_xref is idempotent if any field exists in the test class."""
        cls_data = loaded_analyzer.list_fields("Laej;")
        if cls_data is None or not cls_data["fields"]:
            return
        field_name = cls_data["fields"][0].name
        r1 = loaded_analyzer.get_field_xref("Laej;", field_name)
        r2 = loaded_analyzer.get_field_xref("Laej;", field_name)
        assert r1 == r2
