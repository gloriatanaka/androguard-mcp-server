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
